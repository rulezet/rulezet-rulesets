rule TTP_XOR_QUAD_CurrentVersionRun_a3b3 {
  strings:
    $key_a3b3 = { f0 dc [2] d4 d2 [2] ff fe [2] d1 dc [2] c5 c7 [2] ca dd [2] d4 c0 [2] d6 c1 [2] cd c7 [2] d1 c0 [2] cd ef }

  condition:
    any of them
}