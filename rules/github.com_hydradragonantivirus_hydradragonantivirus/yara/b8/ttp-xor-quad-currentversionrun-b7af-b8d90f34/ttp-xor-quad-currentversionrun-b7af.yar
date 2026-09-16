rule TTP_XOR_QUAD_CurrentVersionRun_b7af {
  strings:
    $key_b7af = { e4 c0 [2] c0 ce [2] eb e2 [2] c5 c0 [2] d1 db [2] de c1 [2] c0 dc [2] c2 dd [2] d9 db [2] c5 dc [2] d9 f3 }

  condition:
    any of them
}