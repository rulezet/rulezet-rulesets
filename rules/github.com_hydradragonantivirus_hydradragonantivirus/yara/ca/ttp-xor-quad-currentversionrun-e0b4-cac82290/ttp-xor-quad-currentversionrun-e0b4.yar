rule TTP_XOR_QUAD_CurrentVersionRun_e0b4 {
  strings:
    $key_e0b4 = { b3 db [2] 97 d5 [2] bc f9 [2] 92 db [2] 86 c0 [2] 89 da [2] 97 c7 [2] 95 c6 [2] 8e c0 [2] 92 c7 [2] 8e e8 }

  condition:
    any of them
}