rule TTP_XOR_WriteProcessMemory_bbf9 {
  strings:
    $key_bbf9 = { ec 8b [2] de a9 [2] d8 9c [2] f6 9c [2] c9 80 }

  condition:
    any of them
}