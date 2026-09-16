rule TTP_XOR_QUAD_CurrentVersionRun_cea8 {
  strings:
    $key_cea8 = { 9d c7 [2] b9 c9 [2] 92 e5 [2] bc c7 [2] a8 dc [2] a7 c6 [2] b9 db [2] bb da [2] a0 dc [2] bc db [2] a0 f4 }

  condition:
    any of them
}