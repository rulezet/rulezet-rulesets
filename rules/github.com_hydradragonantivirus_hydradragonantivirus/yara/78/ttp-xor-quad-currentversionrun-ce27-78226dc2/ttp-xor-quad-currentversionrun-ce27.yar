rule TTP_XOR_QUAD_CurrentVersionRun_ce27 {
  strings:
    $key_ce27 = { 9d 48 [2] b9 46 [2] 92 6a [2] bc 48 [2] a8 53 [2] a7 49 [2] b9 54 [2] bb 55 [2] a0 53 [2] bc 54 [2] a0 7b }

  condition:
    any of them
}