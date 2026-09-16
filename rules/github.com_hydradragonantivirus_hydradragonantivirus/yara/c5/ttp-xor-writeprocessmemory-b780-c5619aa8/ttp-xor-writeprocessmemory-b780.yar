rule TTP_XOR_WriteProcessMemory_b780 {
  strings:
    $key_b780 = { e0 f2 [2] d2 d0 [2] d4 e5 [2] fa e5 [2] c5 f9 }

  condition:
    any of them
}