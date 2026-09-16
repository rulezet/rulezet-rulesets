rule TTP_XOR_WriteProcessMemory_bbf8 {
  strings:
    $key_bbf8 = { ec 8a [2] de a8 [2] d8 9d [2] f6 9d [2] c9 81 }

  condition:
    any of them
}