rule TTP_XOR_WriteProcessMemory_8142 {
  strings:
    $key_8142 = { d6 30 [2] e4 12 [2] e2 27 [2] cc 27 [2] f3 3b }

  condition:
    any of them
}