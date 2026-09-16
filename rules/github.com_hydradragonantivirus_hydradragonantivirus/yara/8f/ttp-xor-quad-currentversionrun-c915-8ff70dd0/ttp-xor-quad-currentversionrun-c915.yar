rule TTP_XOR_QUAD_CurrentVersionRun_c915 {
  strings:
    $key_c915 = { 9a 7a [2] be 74 [2] 95 58 [2] bb 7a [2] af 61 [2] a0 7b [2] be 66 [2] bc 67 [2] a7 61 [2] bb 66 [2] a7 49 }

  condition:
    any of them
}