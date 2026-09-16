rule TTP_XOR_QUAD_CurrentVersionRun_d535 {
  strings:
    $key_d535 = { 86 5a [2] a2 54 [2] 89 78 [2] a7 5a [2] b3 41 [2] bc 5b [2] a2 46 [2] a0 47 [2] bb 41 [2] a7 46 [2] bb 69 }

  condition:
    any of them
}