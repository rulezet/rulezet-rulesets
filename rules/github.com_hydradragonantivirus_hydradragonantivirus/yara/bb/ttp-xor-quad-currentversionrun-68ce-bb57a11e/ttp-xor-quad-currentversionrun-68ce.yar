rule TTP_XOR_QUAD_CurrentVersionRun_68ce {
  strings:
    $key_68ce = { 3b a1 [2] 1f af [2] 34 83 [2] 1a a1 [2] 0e ba [2] 01 a0 [2] 1f bd [2] 1d bc [2] 06 ba [2] 1a bd [2] 06 92 }

  condition:
    any of them
}