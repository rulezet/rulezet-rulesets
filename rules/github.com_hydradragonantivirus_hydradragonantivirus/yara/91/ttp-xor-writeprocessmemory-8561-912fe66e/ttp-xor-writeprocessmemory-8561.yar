rule TTP_XOR_WriteProcessMemory_8561 {
  strings:
    $key_8561 = { d2 13 [2] e0 31 [2] e6 04 [2] c8 04 [2] f7 18 }

  condition:
    any of them
}