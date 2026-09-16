rule TTP_XOR_QUAD_CurrentVersionRun_e0b5 {
  strings:
    $key_e0b5 = { b3 da [2] 97 d4 [2] bc f8 [2] 92 da [2] 86 c1 [2] 89 db [2] 97 c6 [2] 95 c7 [2] 8e c1 [2] 92 c6 [2] 8e e9 }

  condition:
    any of them
}