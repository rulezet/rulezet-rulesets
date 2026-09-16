rule TTP_XOR_WriteProcessMemory_8521 {
  strings:
    $key_8521 = { d2 53 [2] e0 71 [2] e6 44 [2] c8 44 [2] f7 58 }

  condition:
    any of them
}