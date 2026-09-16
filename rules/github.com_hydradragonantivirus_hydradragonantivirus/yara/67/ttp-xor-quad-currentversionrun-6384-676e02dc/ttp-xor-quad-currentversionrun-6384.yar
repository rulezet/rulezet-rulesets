rule TTP_XOR_QUAD_CurrentVersionRun_6384 {
  strings:
    $key_6384 = { 30 eb [2] 14 e5 [2] 3f c9 [2] 11 eb [2] 05 f0 [2] 0a ea [2] 14 f7 [2] 16 f6 [2] 0d f0 [2] 11 f7 [2] 0d d8 }

  condition:
    any of them
}