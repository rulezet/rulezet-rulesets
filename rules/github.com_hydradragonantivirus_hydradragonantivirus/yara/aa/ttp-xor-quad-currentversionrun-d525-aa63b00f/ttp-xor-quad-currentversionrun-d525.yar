rule TTP_XOR_QUAD_CurrentVersionRun_d525 {
  strings:
    $key_d525 = { 86 4a [2] a2 44 [2] 89 68 [2] a7 4a [2] b3 51 [2] bc 4b [2] a2 56 [2] a0 57 [2] bb 51 [2] a7 56 [2] bb 79 }

  condition:
    any of them
}