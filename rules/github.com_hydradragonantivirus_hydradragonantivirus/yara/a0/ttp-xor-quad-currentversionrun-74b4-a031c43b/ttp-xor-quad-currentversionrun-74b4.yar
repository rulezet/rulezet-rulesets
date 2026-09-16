rule TTP_XOR_QUAD_CurrentVersionRun_74b4 {
  strings:
    $key_74b4 = { 27 db [2] 03 d5 [2] 28 f9 [2] 06 db [2] 12 c0 [2] 1d da [2] 03 c7 [2] 01 c6 [2] 1a c0 [2] 06 c7 [2] 1a e8 }

  condition:
    any of them
}