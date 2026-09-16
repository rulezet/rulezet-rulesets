rule TTP_XOR_WriteProcessMemory_8565 {
  strings:
    $key_8565 = { d2 17 [2] e0 35 [2] e6 00 [2] c8 00 [2] f7 1c }

  condition:
    any of them
}