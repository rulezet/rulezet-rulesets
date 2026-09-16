rule TTP_XOR_QUAD_CurrentVersionRun_dad6 {
  strings:
    $key_dad6 = { 89 b9 [2] ad b7 [2] 86 9b [2] a8 b9 [2] bc a2 [2] b3 b8 [2] ad a5 [2] af a4 [2] b4 a2 [2] a8 a5 [2] b4 8a }

  condition:
    any of them
}