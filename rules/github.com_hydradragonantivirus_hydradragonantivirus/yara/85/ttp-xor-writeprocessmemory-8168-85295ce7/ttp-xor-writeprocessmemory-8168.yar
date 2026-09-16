rule TTP_XOR_WriteProcessMemory_8168 {
  strings:
    $key_8168 = { d6 1a [2] e4 38 [2] e2 0d [2] cc 0d [2] f3 11 }

  condition:
    any of them
}