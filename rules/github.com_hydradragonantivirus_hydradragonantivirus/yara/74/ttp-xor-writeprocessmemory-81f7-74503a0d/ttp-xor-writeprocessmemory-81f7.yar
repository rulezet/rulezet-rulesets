rule TTP_XOR_WriteProcessMemory_81f7 {
  strings:
    $key_81f7 = { d6 85 [2] e4 a7 [2] e2 92 [2] cc 92 [2] f3 8e }

  condition:
    any of them
}