rule TTP_XOR_QUAD_CurrentVersionRun_ce7e {
  strings:
    $key_ce7e = { 9d 11 [2] b9 1f [2] 92 33 [2] bc 11 [2] a8 0a [2] a7 10 [2] b9 0d [2] bb 0c [2] a0 0a [2] bc 0d [2] a0 22 }

  condition:
    any of them
}