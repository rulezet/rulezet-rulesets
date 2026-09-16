rule TTP_XOR_QUAD_CurrentVersionRun_d524 {
  strings:
    $key_d524 = { 86 4b [2] a2 45 [2] 89 69 [2] a7 4b [2] b3 50 [2] bc 4a [2] a2 57 [2] a0 56 [2] bb 50 [2] a7 57 [2] bb 78 }

  condition:
    any of them
}