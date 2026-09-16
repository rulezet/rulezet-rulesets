rule TTP_XOR_QUAD_CurrentVersionRun_ce65 {
  strings:
    $key_ce65 = { 9d 0a [2] b9 04 [2] 92 28 [2] bc 0a [2] a8 11 [2] a7 0b [2] b9 16 [2] bb 17 [2] a0 11 [2] bc 16 [2] a0 39 }

  condition:
    any of them
}