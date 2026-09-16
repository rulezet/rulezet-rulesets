rule TTP_XOR_QUAD_CurrentVersionRun_cef3 {
  strings:
    $key_cef3 = { 9d 9c [2] b9 92 [2] 92 be [2] bc 9c [2] a8 87 [2] a7 9d [2] b9 80 [2] bb 81 [2] a0 87 [2] bc 80 [2] a0 af }

  condition:
    any of them
}