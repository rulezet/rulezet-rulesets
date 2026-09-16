rule TTP_XOR_QUAD_CurrentVersionRun_d2a4 {
  strings:
    $key_d2a4 = { 81 cb [2] a5 c5 [2] 8e e9 [2] a0 cb [2] b4 d0 [2] bb ca [2] a5 d7 [2] a7 d6 [2] bc d0 [2] a0 d7 [2] bc f8 }

  condition:
    any of them
}