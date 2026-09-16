rule TTP_XOR_QUAD_CurrentVersionRun_d2f9 {
  strings:
    $key_d2f9 = { 81 96 [2] a5 98 [2] 8e b4 [2] a0 96 [2] b4 8d [2] bb 97 [2] a5 8a [2] a7 8b [2] bc 8d [2] a0 8a [2] bc a5 }

  condition:
    any of them
}