rule TTP_XOR_WriteProcessMemory_8506 {
  strings:
    $key_8506 = { d2 74 [2] e0 56 [2] e6 63 [2] c8 63 [2] f7 7f }

  condition:
    any of them
}