rule TTP_XOR_QUAD_CurrentVersionRun_d504 {
  strings:
    $key_d504 = { 86 6b [2] a2 65 [2] 89 49 [2] a7 6b [2] b3 70 [2] bc 6a [2] a2 77 [2] a0 76 [2] bb 70 [2] a7 77 [2] bb 58 }

  condition:
    any of them
}