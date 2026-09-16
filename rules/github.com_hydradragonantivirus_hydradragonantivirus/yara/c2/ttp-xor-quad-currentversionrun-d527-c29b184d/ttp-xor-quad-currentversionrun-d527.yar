rule TTP_XOR_QUAD_CurrentVersionRun_d527 {
  strings:
    $key_d527 = { 86 48 [2] a2 46 [2] 89 6a [2] a7 48 [2] b3 53 [2] bc 49 [2] a2 54 [2] a0 55 [2] bb 53 [2] a7 54 [2] bb 7b }

  condition:
    any of them
}