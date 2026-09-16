rule TTP_XOR_QUAD_CurrentVersionRun_d56b {
  strings:
    $key_d56b = { 86 04 [2] a2 0a [2] 89 26 [2] a7 04 [2] b3 1f [2] bc 05 [2] a2 18 [2] a0 19 [2] bb 1f [2] a7 18 [2] bb 37 }

  condition:
    any of them
}