rule TTP_XOR_QUAD_CurrentVersionRun_d514 {
  strings:
    $key_d514 = { 86 7b [2] a2 75 [2] 89 59 [2] a7 7b [2] b3 60 [2] bc 7a [2] a2 67 [2] a0 66 [2] bb 60 [2] a7 67 [2] bb 48 }

  condition:
    any of them
}