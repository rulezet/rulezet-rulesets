rule TTP_XOR_QUAD_CurrentVersionRun_a3a9 {
  strings:
    $key_a3a9 = { f0 c6 [2] d4 c8 [2] ff e4 [2] d1 c6 [2] c5 dd [2] ca c7 [2] d4 da [2] d6 db [2] cd dd [2] d1 da [2] cd f5 }

  condition:
    any of them
}