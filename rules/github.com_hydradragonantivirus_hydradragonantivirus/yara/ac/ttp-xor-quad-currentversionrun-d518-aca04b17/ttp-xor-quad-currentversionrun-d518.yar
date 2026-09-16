rule TTP_XOR_QUAD_CurrentVersionRun_d518 {
  strings:
    $key_d518 = { 86 77 [2] a2 79 [2] 89 55 [2] a7 77 [2] b3 6c [2] bc 76 [2] a2 6b [2] a0 6a [2] bb 6c [2] a7 6b [2] bb 44 }

  condition:
    any of them
}