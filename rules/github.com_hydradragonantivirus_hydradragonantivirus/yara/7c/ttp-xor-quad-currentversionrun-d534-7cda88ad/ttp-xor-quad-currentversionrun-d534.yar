rule TTP_XOR_QUAD_CurrentVersionRun_d534 {
  strings:
    $key_d534 = { 86 5b [2] a2 55 [2] 89 79 [2] a7 5b [2] b3 40 [2] bc 5a [2] a2 47 [2] a0 46 [2] bb 40 [2] a7 47 [2] bb 68 }

  condition:
    any of them
}