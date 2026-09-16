rule TTP_XOR_QUAD_CurrentVersionRun_bfa8 {
  strings:
    $key_bfa8 = { ec c7 [2] c8 c9 [2] e3 e5 [2] cd c7 [2] d9 dc [2] d6 c6 [2] c8 db [2] ca da [2] d1 dc [2] cd db [2] d1 f4 }

  condition:
    any of them
}