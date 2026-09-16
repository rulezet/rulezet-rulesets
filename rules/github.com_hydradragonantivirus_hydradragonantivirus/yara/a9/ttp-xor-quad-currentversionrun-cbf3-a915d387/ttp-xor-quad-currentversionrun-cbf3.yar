rule TTP_XOR_QUAD_CurrentVersionRun_cbf3 {
  strings:
    $key_cbf3 = { 98 9c [2] bc 92 [2] 97 be [2] b9 9c [2] ad 87 [2] a2 9d [2] bc 80 [2] be 81 [2] a5 87 [2] b9 80 [2] a5 af }

  condition:
    any of them
}