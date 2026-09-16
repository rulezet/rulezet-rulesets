rule TTP_XOR_QUAD_CurrentVersionRun_d546 {
  strings:
    $key_d546 = { 86 29 [2] a2 27 [2] 89 0b [2] a7 29 [2] b3 32 [2] bc 28 [2] a2 35 [2] a0 34 [2] bb 32 [2] a7 35 [2] bb 1a }

  condition:
    any of them
}