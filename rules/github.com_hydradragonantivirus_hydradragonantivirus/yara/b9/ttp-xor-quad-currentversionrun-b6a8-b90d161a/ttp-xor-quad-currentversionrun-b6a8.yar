rule TTP_XOR_QUAD_CurrentVersionRun_b6a8 {
  strings:
    $key_b6a8 = { e5 c7 [2] c1 c9 [2] ea e5 [2] c4 c7 [2] d0 dc [2] df c6 [2] c1 db [2] c3 da [2] d8 dc [2] c4 db [2] d8 f4 }

  condition:
    any of them
}