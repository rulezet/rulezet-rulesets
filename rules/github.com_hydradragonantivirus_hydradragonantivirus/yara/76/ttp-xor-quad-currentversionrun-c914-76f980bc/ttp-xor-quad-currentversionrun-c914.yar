rule TTP_XOR_QUAD_CurrentVersionRun_c914 {
  strings:
    $key_c914 = { 9a 7b [2] be 75 [2] 95 59 [2] bb 7b [2] af 60 [2] a0 7a [2] be 67 [2] bc 66 [2] a7 60 [2] bb 67 [2] a7 48 }

  condition:
    any of them
}