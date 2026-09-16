rule TTP_XOR_QUAD_CurrentVersionRun_4686 {
  strings:
    $key_4686 = { 15 e9 [2] 31 e7 [2] 1a cb [2] 34 e9 [2] 20 f2 [2] 2f e8 [2] 31 f5 [2] 33 f4 [2] 28 f2 [2] 34 f5 [2] 28 da }

  condition:
    any of them
}