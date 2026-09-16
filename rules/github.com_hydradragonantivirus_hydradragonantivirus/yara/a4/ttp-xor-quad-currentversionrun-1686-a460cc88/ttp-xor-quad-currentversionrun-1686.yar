rule TTP_XOR_QUAD_CurrentVersionRun_1686 {
  strings:
    $key_1686 = { 45 e9 [2] 61 e7 [2] 4a cb [2] 64 e9 [2] 70 f2 [2] 7f e8 [2] 61 f5 [2] 63 f4 [2] 78 f2 [2] 64 f5 [2] 78 da }

  condition:
    any of them
}