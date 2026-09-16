rule TTP_XOR_QUAD_CurrentVersionRun_c939 {
  strings:
    $key_c939 = { 9a 56 [2] be 58 [2] 95 74 [2] bb 56 [2] af 4d [2] a0 57 [2] be 4a [2] bc 4b [2] a7 4d [2] bb 4a [2] a7 65 }

  condition:
    any of them
}