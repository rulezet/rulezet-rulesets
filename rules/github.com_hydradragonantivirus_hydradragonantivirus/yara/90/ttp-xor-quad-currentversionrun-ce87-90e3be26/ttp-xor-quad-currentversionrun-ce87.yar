rule TTP_XOR_QUAD_CurrentVersionRun_ce87 {
  strings:
    $key_ce87 = { 9d e8 [2] b9 e6 [2] 92 ca [2] bc e8 [2] a8 f3 [2] a7 e9 [2] b9 f4 [2] bb f5 [2] a0 f3 [2] bc f4 [2] a0 db }

  condition:
    any of them
}