rule TTP_XOR_QUAD_CurrentVersionRun_ce3e {
  strings:
    $key_ce3e = { 9d 51 [2] b9 5f [2] 92 73 [2] bc 51 [2] a8 4a [2] a7 50 [2] b9 4d [2] bb 4c [2] a0 4a [2] bc 4d [2] a0 62 }

  condition:
    any of them
}