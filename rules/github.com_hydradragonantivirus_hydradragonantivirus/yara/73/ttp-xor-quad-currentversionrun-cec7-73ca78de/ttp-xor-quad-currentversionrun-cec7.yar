rule TTP_XOR_QUAD_CurrentVersionRun_cec7 {
  strings:
    $key_cec7 = { 9d a8 [2] b9 a6 [2] 92 8a [2] bc a8 [2] a8 b3 [2] a7 a9 [2] b9 b4 [2] bb b5 [2] a0 b3 [2] bc b4 [2] a0 9b }

  condition:
    any of them
}