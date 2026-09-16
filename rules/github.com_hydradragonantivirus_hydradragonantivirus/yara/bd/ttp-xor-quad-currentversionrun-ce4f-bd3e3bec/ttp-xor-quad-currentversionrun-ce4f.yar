rule TTP_XOR_QUAD_CurrentVersionRun_ce4f {
  strings:
    $key_ce4f = { 9d 20 [2] b9 2e [2] 92 02 [2] bc 20 [2] a8 3b [2] a7 21 [2] b9 3c [2] bb 3d [2] a0 3b [2] bc 3c [2] a0 13 }

  condition:
    any of them
}