rule TTP_XOR_QUAD_CurrentVersionRun_ce3a {
  strings:
    $key_ce3a = { 9d 55 [2] b9 5b [2] 92 77 [2] bc 55 [2] a8 4e [2] a7 54 [2] b9 49 [2] bb 48 [2] a0 4e [2] bc 49 [2] a0 66 }

  condition:
    any of them
}