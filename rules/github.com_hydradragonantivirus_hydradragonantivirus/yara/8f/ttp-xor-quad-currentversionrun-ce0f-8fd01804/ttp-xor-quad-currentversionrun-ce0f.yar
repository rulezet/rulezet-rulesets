rule TTP_XOR_QUAD_CurrentVersionRun_ce0f {
  strings:
    $key_ce0f = { 9d 60 [2] b9 6e [2] 92 42 [2] bc 60 [2] a8 7b [2] a7 61 [2] b9 7c [2] bb 7d [2] a0 7b [2] bc 7c [2] a0 53 }

  condition:
    any of them
}