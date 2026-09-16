rule TTP_XOR_QUAD_CurrentVersionRun_c908 {
  strings:
    $key_c908 = { 9a 67 [2] be 69 [2] 95 45 [2] bb 67 [2] af 7c [2] a0 66 [2] be 7b [2] bc 7a [2] a7 7c [2] bb 7b [2] a7 54 }

  condition:
    any of them
}