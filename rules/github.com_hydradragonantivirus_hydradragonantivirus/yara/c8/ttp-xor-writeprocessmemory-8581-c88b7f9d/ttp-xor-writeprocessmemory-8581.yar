rule TTP_XOR_WriteProcessMemory_8581 {
  strings:
    $key_8581 = { d2 f3 [2] e0 d1 [2] e6 e4 [2] c8 e4 [2] f7 f8 }

  condition:
    any of them
}