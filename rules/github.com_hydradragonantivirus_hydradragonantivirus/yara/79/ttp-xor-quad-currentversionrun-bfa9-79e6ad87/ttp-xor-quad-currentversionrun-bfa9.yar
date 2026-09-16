rule TTP_XOR_QUAD_CurrentVersionRun_bfa9 {
  strings:
    $key_bfa9 = { ec c6 [2] c8 c8 [2] e3 e4 [2] cd c6 [2] d9 dd [2] d6 c7 [2] c8 da [2] ca db [2] d1 dd [2] cd da [2] d1 f5 }

  condition:
    any of them
}