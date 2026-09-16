rule TTP_XOR_QUAD_CurrentVersionRun_ce49 {
  strings:
    $key_ce49 = { 9d 26 [2] b9 28 [2] 92 04 [2] bc 26 [2] a8 3d [2] a7 27 [2] b9 3a [2] bb 3b [2] a0 3d [2] bc 3a [2] a0 15 }

  condition:
    any of them
}