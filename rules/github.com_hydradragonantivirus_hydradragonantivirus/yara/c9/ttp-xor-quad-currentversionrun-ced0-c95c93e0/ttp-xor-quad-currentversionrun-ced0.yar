rule TTP_XOR_QUAD_CurrentVersionRun_ced0 {
  strings:
    $key_ced0 = { 9d bf [2] b9 b1 [2] 92 9d [2] bc bf [2] a8 a4 [2] a7 be [2] b9 a3 [2] bb a2 [2] a0 a4 [2] bc a3 [2] a0 8c }

  condition:
    any of them
}