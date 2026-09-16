rule TTP_XOR_QUAD_CurrentVersionRun_7384 {
  strings:
    $key_7384 = { 20 eb [2] 04 e5 [2] 2f c9 [2] 01 eb [2] 15 f0 [2] 1a ea [2] 04 f7 [2] 06 f6 [2] 1d f0 [2] 01 f7 [2] 1d d8 }

  condition:
    any of them
}