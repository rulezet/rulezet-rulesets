rule TTP_XOR_QUAD_CurrentVersionRun_ce1f {
  strings:
    $key_ce1f = { 9d 70 [2] b9 7e [2] 92 52 [2] bc 70 [2] a8 6b [2] a7 71 [2] b9 6c [2] bb 6d [2] a0 6b [2] bc 6c [2] a0 43 }

  condition:
    any of them
}