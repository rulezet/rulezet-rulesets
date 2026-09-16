rule TTP_XOR_QUAD_CurrentVersionRun_91cf {
  strings:
    $key_91cf = { c2 a0 [2] e6 ae [2] cd 82 [2] e3 a0 [2] f7 bb [2] f8 a1 [2] e6 bc [2] e4 bd [2] ff bb [2] e3 bc [2] ff 93 }

  condition:
    any of them
}