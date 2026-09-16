rule TTP_XOR_WriteProcessMemory_a0b4 {
  strings:
    $key_a0b4 = { f7 c6 [2] c5 e4 [2] c3 d1 [2] ed d1 [2] d2 cd }

  condition:
    any of them
}