rule TTP_XOR_QUAD_CurrentVersionRun_d508 {
  strings:
    $key_d508 = { 86 67 [2] a2 69 [2] 89 45 [2] a7 67 [2] b3 7c [2] bc 66 [2] a2 7b [2] a0 7a [2] bb 7c [2] a7 7b [2] bb 54 }

  condition:
    any of them
}