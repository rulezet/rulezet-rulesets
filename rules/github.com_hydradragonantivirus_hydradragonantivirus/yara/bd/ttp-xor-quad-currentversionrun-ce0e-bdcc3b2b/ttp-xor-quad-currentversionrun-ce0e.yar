rule TTP_XOR_QUAD_CurrentVersionRun_ce0e {
  strings:
    $key_ce0e = { 9d 61 [2] b9 6f [2] 92 43 [2] bc 61 [2] a8 7a [2] a7 60 [2] b9 7d [2] bb 7c [2] a0 7a [2] bc 7d [2] a0 52 }

  condition:
    any of them
}