rule TTP_XOR_WriteProcessMemory_8551 {
  strings:
    $key_8551 = { d2 23 [2] e0 01 [2] e6 34 [2] c8 34 [2] f7 28 }

  condition:
    any of them
}