rule TTP_XOR_QUAD_CurrentVersionRun_ce03 {
  strings:
    $key_ce03 = { 9d 6c [2] b9 62 [2] 92 4e [2] bc 6c [2] a8 77 [2] a7 6d [2] b9 70 [2] bb 71 [2] a0 77 [2] bc 70 [2] a0 5f }

  condition:
    any of them
}