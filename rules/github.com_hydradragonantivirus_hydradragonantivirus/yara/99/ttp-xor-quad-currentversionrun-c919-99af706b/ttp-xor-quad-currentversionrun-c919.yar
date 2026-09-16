rule TTP_XOR_QUAD_CurrentVersionRun_c919 {
  strings:
    $key_c919 = { 9a 76 [2] be 78 [2] 95 54 [2] bb 76 [2] af 6d [2] a0 77 [2] be 6a [2] bc 6b [2] a7 6d [2] bb 6a [2] a7 45 }

  condition:
    any of them
}