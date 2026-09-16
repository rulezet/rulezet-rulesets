rule TTP_XOR_QUAD_CurrentVersionRun_c935 {
  strings:
    $key_c935 = { 9a 5a [2] be 54 [2] 95 78 [2] bb 5a [2] af 41 [2] a0 5b [2] be 46 [2] bc 47 [2] a7 41 [2] bb 46 [2] a7 69 }

  condition:
    any of them
}