rule TTP_XOR_QUAD_CurrentVersionRun_b6a9 {
  strings:
    $key_b6a9 = { e5 c6 [2] c1 c8 [2] ea e4 [2] c4 c6 [2] d0 dd [2] df c7 [2] c1 da [2] c3 db [2] d8 dd [2] c4 da [2] d8 f5 }

  condition:
    any of them
}