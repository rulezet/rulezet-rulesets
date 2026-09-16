rule TTP_XOR_QUAD_CurrentVersionRun_cec9 {
  strings:
    $key_cec9 = { 9d a6 [2] b9 a8 [2] 92 84 [2] bc a6 [2] a8 bd [2] a7 a7 [2] b9 ba [2] bb bb [2] a0 bd [2] bc ba [2] a0 95 }

  condition:
    any of them
}