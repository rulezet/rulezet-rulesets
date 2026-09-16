rule TTP_XOR_QUAD_CurrentVersionRun_bccf {
  strings:
    $key_bccf = { ef a0 [2] cb ae [2] e0 82 [2] ce a0 [2] da bb [2] d5 a1 [2] cb bc [2] c9 bd [2] d2 bb [2] ce bc [2] d2 93 }

  condition:
    any of them
}