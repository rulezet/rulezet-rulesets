rule TTP_XOR_QUAD_CurrentVersionRun_d211 {
  strings:
    $key_d211 = { 81 7e [2] a5 70 [2] 8e 5c [2] a0 7e [2] b4 65 [2] bb 7f [2] a5 62 [2] a7 63 [2] bc 65 [2] a0 62 [2] bc 4d }

  condition:
    any of them
}