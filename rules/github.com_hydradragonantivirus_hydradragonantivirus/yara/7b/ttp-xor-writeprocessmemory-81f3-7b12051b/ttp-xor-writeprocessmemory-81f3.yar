rule TTP_XOR_WriteProcessMemory_81f3 {
  strings:
    $key_81f3 = { d6 81 [2] e4 a3 [2] e2 96 [2] cc 96 [2] f3 8a }

  condition:
    any of them
}