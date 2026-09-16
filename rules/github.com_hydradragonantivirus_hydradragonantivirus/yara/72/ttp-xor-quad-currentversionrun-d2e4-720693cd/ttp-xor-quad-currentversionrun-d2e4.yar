rule TTP_XOR_QUAD_CurrentVersionRun_d2e4 {
  strings:
    $key_d2e4 = { 81 8b [2] a5 85 [2] 8e a9 [2] a0 8b [2] b4 90 [2] bb 8a [2] a5 97 [2] a7 96 [2] bc 90 [2] a0 97 [2] bc b8 }

  condition:
    any of them
}