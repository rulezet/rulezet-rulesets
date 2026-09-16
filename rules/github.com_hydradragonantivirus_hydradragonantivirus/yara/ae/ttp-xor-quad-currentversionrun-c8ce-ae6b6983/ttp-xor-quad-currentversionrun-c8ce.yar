rule TTP_XOR_QUAD_CurrentVersionRun_c8ce {
  strings:
    $key_c8ce = { 9b a1 [2] bf af [2] 94 83 [2] ba a1 [2] ae ba [2] a1 a0 [2] bf bd [2] bd bc [2] a6 ba [2] ba bd [2] a6 92 }

  condition:
    any of them
}