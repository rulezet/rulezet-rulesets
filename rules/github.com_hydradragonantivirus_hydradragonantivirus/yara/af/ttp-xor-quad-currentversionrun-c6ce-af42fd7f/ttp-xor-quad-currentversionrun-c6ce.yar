rule TTP_XOR_QUAD_CurrentVersionRun_c6ce {
  strings:
    $key_c6ce = { 95 a1 [2] b1 af [2] 9a 83 [2] b4 a1 [2] a0 ba [2] af a0 [2] b1 bd [2] b3 bc [2] a8 ba [2] b4 bd [2] a8 92 }

  condition:
    any of them
}