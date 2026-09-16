rule TTP_XOR_QUAD_CurrentVersionRun_ce86 {
  strings:
    $key_ce86 = { 9d e9 [2] b9 e7 [2] 92 cb [2] bc e9 [2] a8 f2 [2] a7 e8 [2] b9 f5 [2] bb f4 [2] a0 f2 [2] bc f5 [2] a0 da }

  condition:
    any of them
}