rule TTP_XOR_WriteProcessMemory_b481 {
  strings:
    $key_b481 = { e3 f3 [2] d1 d1 [2] d7 e4 [2] f9 e4 [2] c6 f8 }

  condition:
    any of them
}