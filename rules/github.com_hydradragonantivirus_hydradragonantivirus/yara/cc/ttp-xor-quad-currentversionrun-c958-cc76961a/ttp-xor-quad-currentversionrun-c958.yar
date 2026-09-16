rule TTP_XOR_QUAD_CurrentVersionRun_c958 {
  strings:
    $key_c958 = { 9a 37 [2] be 39 [2] 95 15 [2] bb 37 [2] af 2c [2] a0 36 [2] be 2b [2] bc 2a [2] a7 2c [2] bb 2b [2] a7 04 }

  condition:
    any of them
}