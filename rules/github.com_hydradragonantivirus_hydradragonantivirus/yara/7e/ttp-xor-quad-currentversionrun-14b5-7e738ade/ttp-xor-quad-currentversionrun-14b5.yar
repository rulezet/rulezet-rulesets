rule TTP_XOR_QUAD_CurrentVersionRun_14b5 {
  strings:
    $key_14b5 = { 47 da [2] 63 d4 [2] 48 f8 [2] 66 da [2] 72 c1 [2] 7d db [2] 63 c6 [2] 61 c7 [2] 7a c1 [2] 66 c6 [2] 7a e9 }

  condition:
    any of them
}