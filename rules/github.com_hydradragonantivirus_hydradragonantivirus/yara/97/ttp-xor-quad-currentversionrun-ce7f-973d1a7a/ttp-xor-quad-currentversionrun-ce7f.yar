rule TTP_XOR_QUAD_CurrentVersionRun_ce7f {
  strings:
    $key_ce7f = { 9d 10 [2] b9 1e [2] 92 32 [2] bc 10 [2] a8 0b [2] a7 11 [2] b9 0c [2] bb 0d [2] a0 0b [2] bc 0c [2] a0 23 }

  condition:
    any of them
}