rule TTP_XOR_QUAD_CurrentVersionRun_c929 {
  strings:
    $key_c929 = { 9a 46 [2] be 48 [2] 95 64 [2] bb 46 [2] af 5d [2] a0 47 [2] be 5a [2] bc 5b [2] a7 5d [2] bb 5a [2] a7 75 }

  condition:
    any of them
}