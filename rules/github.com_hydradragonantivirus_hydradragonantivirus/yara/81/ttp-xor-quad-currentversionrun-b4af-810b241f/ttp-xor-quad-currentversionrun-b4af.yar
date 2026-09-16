rule TTP_XOR_QUAD_CurrentVersionRun_b4af {
  strings:
    $key_b4af = { e7 c0 [2] c3 ce [2] e8 e2 [2] c6 c0 [2] d2 db [2] dd c1 [2] c3 dc [2] c1 dd [2] da db [2] c6 dc [2] da f3 }

  condition:
    any of them
}