rule TTP_XOR_QUAD_CurrentVersionRun_7786 {
  strings:
    $key_7786 = { 24 e9 [2] 00 e7 [2] 2b cb [2] 05 e9 [2] 11 f2 [2] 1e e8 [2] 00 f5 [2] 02 f4 [2] 19 f2 [2] 05 f5 [2] 19 da }

  condition:
    any of them
}