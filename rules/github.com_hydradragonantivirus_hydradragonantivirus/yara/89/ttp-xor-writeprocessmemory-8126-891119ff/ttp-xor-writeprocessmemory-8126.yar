rule TTP_XOR_WriteProcessMemory_8126 {
  strings:
    $key_8126 = { d6 54 [2] e4 76 [2] e2 43 [2] cc 43 [2] f3 5f }

  condition:
    any of them
}