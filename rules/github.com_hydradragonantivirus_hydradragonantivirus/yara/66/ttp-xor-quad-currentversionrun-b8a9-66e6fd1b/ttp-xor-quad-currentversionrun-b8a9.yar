rule TTP_XOR_QUAD_CurrentVersionRun_b8a9 {
  strings:
    $key_b8a9 = { eb c6 [2] cf c8 [2] e4 e4 [2] ca c6 [2] de dd [2] d1 c7 [2] cf da [2] cd db [2] d6 dd [2] ca da [2] d6 f5 }

  condition:
    any of them
}