rule TTP_XOR_WriteProcessMemory_8100 {
  strings:
    $key_8100 = { d6 72 [2] e4 50 [2] e2 65 [2] cc 65 [2] f3 79 }

  condition:
    any of them
}