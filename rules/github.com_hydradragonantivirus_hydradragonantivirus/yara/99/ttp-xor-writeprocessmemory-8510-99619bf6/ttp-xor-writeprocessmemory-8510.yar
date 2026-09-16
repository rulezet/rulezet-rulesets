rule TTP_XOR_WriteProcessMemory_8510 {
  strings:
    $key_8510 = { d2 62 [2] e0 40 [2] e6 75 [2] c8 75 [2] f7 69 }

  condition:
    any of them
}