rule TTP_XOR_QUAD_CurrentVersionRun_ce3b {
  strings:
    $key_ce3b = { 9d 54 [2] b9 5a [2] 92 76 [2] bc 54 [2] a8 4f [2] a7 55 [2] b9 48 [2] bb 49 [2] a0 4f [2] bc 48 [2] a0 67 }

  condition:
    any of them
}