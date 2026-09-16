rule TTP_XOR_QUAD_CurrentVersionRun_d2b8 {
  strings:
    $key_d2b8 = { 81 d7 [2] a5 d9 [2] 8e f5 [2] a0 d7 [2] b4 cc [2] bb d6 [2] a5 cb [2] a7 ca [2] bc cc [2] a0 cb [2] bc e4 }

  condition:
    any of them
}