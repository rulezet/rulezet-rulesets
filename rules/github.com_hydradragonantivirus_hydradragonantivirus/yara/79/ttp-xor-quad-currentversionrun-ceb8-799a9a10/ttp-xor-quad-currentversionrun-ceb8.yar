rule TTP_XOR_QUAD_CurrentVersionRun_ceb8 {
  strings:
    $key_ceb8 = { 9d d7 [2] b9 d9 [2] 92 f5 [2] bc d7 [2] a8 cc [2] a7 d6 [2] b9 cb [2] bb ca [2] a0 cc [2] bc cb [2] a0 e4 }

  condition:
    any of them
}