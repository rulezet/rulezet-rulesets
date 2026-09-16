rule TTP_XOR_QUAD_CurrentVersionRun_d528 {
  strings:
    $key_d528 = { 86 47 [2] a2 49 [2] 89 65 [2] a7 47 [2] b3 5c [2] bc 46 [2] a2 5b [2] a0 5a [2] bb 5c [2] a7 5b [2] bb 74 }

  condition:
    any of them
}