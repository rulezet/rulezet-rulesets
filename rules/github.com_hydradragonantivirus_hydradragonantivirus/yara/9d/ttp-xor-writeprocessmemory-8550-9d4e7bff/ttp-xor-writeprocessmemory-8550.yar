rule TTP_XOR_WriteProcessMemory_8550 {
  strings:
    $key_8550 = { d2 22 [2] e0 00 [2] e6 35 [2] c8 35 [2] f7 29 }

  condition:
    any of them
}