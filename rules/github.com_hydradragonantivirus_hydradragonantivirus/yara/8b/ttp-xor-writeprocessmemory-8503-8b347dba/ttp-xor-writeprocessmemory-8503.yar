rule TTP_XOR_WriteProcessMemory_8503 {
  strings:
    $key_8503 = { d2 71 [2] e0 53 [2] e6 66 [2] c8 66 [2] f7 7a }

  condition:
    any of them
}