rule TTP_XOR_QUAD_CurrentVersionRun_c924 {
  strings:
    $key_c924 = { 9a 4b [2] be 45 [2] 95 69 [2] bb 4b [2] af 50 [2] a0 4a [2] be 57 [2] bc 56 [2] a7 50 [2] bb 57 [2] a7 78 }

  condition:
    any of them
}