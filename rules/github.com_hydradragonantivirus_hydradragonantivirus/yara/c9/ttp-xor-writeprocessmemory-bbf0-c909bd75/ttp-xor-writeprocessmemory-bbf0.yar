rule TTP_XOR_WriteProcessMemory_bbf0 {
  strings:
    $key_bbf0 = { ec 82 [2] de a0 [2] d8 95 [2] f6 95 [2] c9 89 }

  condition:
    any of them
}