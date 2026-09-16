rule TTP_XOR_WriteProcessMemory_8143 {
  strings:
    $key_8143 = { d6 31 [2] e4 13 [2] e2 26 [2] cc 26 [2] f3 3a }

  condition:
    any of them
}