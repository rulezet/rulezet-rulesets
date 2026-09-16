rule TTP_XOR_QUAD_CurrentVersionRun_44b5 {
  strings:
    $key_44b5 = { 17 da [2] 33 d4 [2] 18 f8 [2] 36 da [2] 22 c1 [2] 2d db [2] 33 c6 [2] 31 c7 [2] 2a c1 [2] 36 c6 [2] 2a e9 }

  condition:
    any of them
}