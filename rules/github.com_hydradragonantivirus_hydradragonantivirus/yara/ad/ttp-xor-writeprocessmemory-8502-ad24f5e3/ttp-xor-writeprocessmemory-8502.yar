rule TTP_XOR_WriteProcessMemory_8502 {
  strings:
    $key_8502 = { d2 70 [2] e0 52 [2] e6 67 [2] c8 67 [2] f7 7b }

  condition:
    any of them
}