rule TTP_XOR_QUAD_CurrentVersionRun_d2fb {
  strings:
    $key_d2fb = { 81 94 [2] a5 9a [2] 8e b6 [2] a0 94 [2] b4 8f [2] bb 95 [2] a5 88 [2] a7 89 [2] bc 8f [2] a0 88 [2] bc a7 }

  condition:
    any of them
}