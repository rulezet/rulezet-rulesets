rule TTP_XOR_QUAD_CurrentVersionRun_c928 {
  strings:
    $key_c928 = { 9a 47 [2] be 49 [2] 95 65 [2] bb 47 [2] af 5c [2] a0 46 [2] be 5b [2] bc 5a [2] a7 5c [2] bb 5b [2] a7 74 }

  condition:
    any of them
}