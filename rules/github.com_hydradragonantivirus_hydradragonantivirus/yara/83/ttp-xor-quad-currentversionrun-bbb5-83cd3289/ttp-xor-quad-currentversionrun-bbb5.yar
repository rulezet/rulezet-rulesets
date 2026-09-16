rule TTP_XOR_QUAD_CurrentVersionRun_bbb5 {
  strings:
    $key_bbb5 = { e8 da [2] cc d4 [2] e7 f8 [2] c9 da [2] dd c1 [2] d2 db [2] cc c6 [2] ce c7 [2] d5 c1 [2] c9 c6 [2] d5 e9 }

  condition:
    any of them
}