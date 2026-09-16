rule TTP_XOR_QUAD_CurrentVersionRun_d566 {
  strings:
    $key_d566 = { 86 09 [2] a2 07 [2] 89 2b [2] a7 09 [2] b3 12 [2] bc 08 [2] a2 15 [2] a0 14 [2] bb 12 [2] a7 15 [2] bb 3a }

  condition:
    any of them
}