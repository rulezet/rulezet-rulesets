rule TTP_XOR_QUAD_CurrentVersionRun_b7a9 {
  strings:
    $key_b7a9 = { e4 c6 [2] c0 c8 [2] eb e4 [2] c5 c6 [2] d1 dd [2] de c7 [2] c0 da [2] c2 db [2] d9 dd [2] c5 da [2] d9 f5 }

  condition:
    any of them
}