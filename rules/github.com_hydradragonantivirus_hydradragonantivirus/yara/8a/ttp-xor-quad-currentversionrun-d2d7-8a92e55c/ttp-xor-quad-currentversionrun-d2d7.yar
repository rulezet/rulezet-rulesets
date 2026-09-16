rule TTP_XOR_QUAD_CurrentVersionRun_d2d7 {
  strings:
    $key_d2d7 = { 81 b8 [2] a5 b6 [2] 8e 9a [2] a0 b8 [2] b4 a3 [2] bb b9 [2] a5 a4 [2] a7 a5 [2] bc a3 [2] a0 a4 [2] bc 8b }

  condition:
    any of them
}