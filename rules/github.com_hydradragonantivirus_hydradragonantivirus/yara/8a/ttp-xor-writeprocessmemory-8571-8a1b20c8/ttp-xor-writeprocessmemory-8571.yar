rule TTP_XOR_WriteProcessMemory_8571 {
  strings:
    $key_8571 = { d2 03 [2] e0 21 [2] e6 14 [2] c8 14 [2] f7 08 }

  condition:
    any of them
}