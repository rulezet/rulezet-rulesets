rule TTP_XOR_QUAD_CurrentVersionRun_d2d1 {
  strings:
    $key_d2d1 = { 81 be [2] a5 b0 [2] 8e 9c [2] a0 be [2] b4 a5 [2] bb bf [2] a5 a2 [2] a7 a3 [2] bc a5 [2] a0 a2 [2] bc 8d }

  condition:
    any of them
}