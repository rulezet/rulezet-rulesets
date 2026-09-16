rule TTP_XOR_WriteProcessMemory_8548 {
  strings:
    $key_8548 = { d2 3a [2] e0 18 [2] e6 2d [2] c8 2d [2] f7 31 }

  condition:
    any of them
}