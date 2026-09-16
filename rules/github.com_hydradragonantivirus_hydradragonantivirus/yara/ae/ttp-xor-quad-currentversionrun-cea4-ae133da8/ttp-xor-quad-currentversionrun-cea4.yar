rule TTP_XOR_QUAD_CurrentVersionRun_cea4 {
  strings:
    $key_cea4 = { 9d cb [2] b9 c5 [2] 92 e9 [2] bc cb [2] a8 d0 [2] a7 ca [2] b9 d7 [2] bb d6 [2] a0 d0 [2] bc d7 [2] a0 f8 }

  condition:
    any of them
}