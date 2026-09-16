rule TTP_XOR_WriteProcessMemory_b7b4 {
  strings:
    $key_b7b4 = { e0 c6 [2] d2 e4 [2] d4 d1 [2] fa d1 [2] c5 cd }

  condition:
    any of them
}