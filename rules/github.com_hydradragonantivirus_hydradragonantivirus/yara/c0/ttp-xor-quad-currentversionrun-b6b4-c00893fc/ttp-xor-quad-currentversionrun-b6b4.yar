rule TTP_XOR_QUAD_CurrentVersionRun_b6b4 {
  strings:
    $key_b6b4 = { e5 db [2] c1 d5 [2] ea f9 [2] c4 db [2] d0 c0 [2] df da [2] c1 c7 [2] c3 c6 [2] d8 c0 [2] c4 c7 [2] d8 e8 }

  condition:
    any of them
}