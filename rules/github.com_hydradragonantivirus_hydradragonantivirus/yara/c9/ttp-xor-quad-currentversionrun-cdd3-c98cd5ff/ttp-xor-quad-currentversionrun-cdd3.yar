rule TTP_XOR_QUAD_CurrentVersionRun_cdd3 {
  strings:
    $key_cdd3 = { 9e bc [2] ba b2 [2] 91 9e [2] bf bc [2] ab a7 [2] a4 bd [2] ba a0 [2] b8 a1 [2] a3 a7 [2] bf a0 [2] a3 8f }

  condition:
    any of them
}