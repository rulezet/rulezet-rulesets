rule TTP_XOR_QUAD_CurrentVersionRun_c905 {
  strings:
    $key_c905 = { 9a 6a [2] be 64 [2] 95 48 [2] bb 6a [2] af 71 [2] a0 6b [2] be 76 [2] bc 77 [2] a7 71 [2] bb 76 [2] a7 59 }

  condition:
    any of them
}