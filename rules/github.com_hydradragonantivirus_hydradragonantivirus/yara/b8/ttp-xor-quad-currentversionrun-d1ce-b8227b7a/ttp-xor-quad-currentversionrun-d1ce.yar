rule TTP_XOR_QUAD_CurrentVersionRun_d1ce {
  strings:
    $key_d1ce = { 82 a1 [2] a6 af [2] 8d 83 [2] a3 a1 [2] b7 ba [2] b8 a0 [2] a6 bd [2] a4 bc [2] bf ba [2] a3 bd [2] bf 92 }

  condition:
    any of them
}