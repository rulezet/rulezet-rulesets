rule TTP_XOR_QUAD_CurrentVersionRun_ce13 {
  strings:
    $key_ce13 = { 9d 7c [2] b9 72 [2] 92 5e [2] bc 7c [2] a8 67 [2] a7 7d [2] b9 60 [2] bb 61 [2] a0 67 [2] bc 60 [2] a0 4f }

  condition:
    any of them
}