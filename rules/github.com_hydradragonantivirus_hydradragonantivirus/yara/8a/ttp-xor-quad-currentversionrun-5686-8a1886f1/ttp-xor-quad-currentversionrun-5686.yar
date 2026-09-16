rule TTP_XOR_QUAD_CurrentVersionRun_5686 {
  strings:
    $key_5686 = { 05 e9 [2] 21 e7 [2] 0a cb [2] 24 e9 [2] 30 f2 [2] 3f e8 [2] 21 f5 [2] 23 f4 [2] 38 f2 [2] 24 f5 [2] 38 da }

  condition:
    any of them
}