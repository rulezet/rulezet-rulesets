rule TTP_XOR_QUAD_CurrentVersionRun_2686 {
  strings:
    $key_2686 = { 75 e9 [2] 51 e7 [2] 7a cb [2] 54 e9 [2] 40 f2 [2] 4f e8 [2] 51 f5 [2] 53 f4 [2] 48 f2 [2] 54 f5 [2] 48 da }

  condition:
    any of them
}