rule TTP_XOR_QUAD_CurrentVersionRun_419a {
  strings:
    $key_419a = { 12 f5 [2] 36 fb [2] 1d d7 [2] 33 f5 [2] 27 ee [2] 28 f4 [2] 36 e9 [2] 34 e8 [2] 2f ee [2] 33 e9 [2] 2f c6 }

  condition:
    any of them
}