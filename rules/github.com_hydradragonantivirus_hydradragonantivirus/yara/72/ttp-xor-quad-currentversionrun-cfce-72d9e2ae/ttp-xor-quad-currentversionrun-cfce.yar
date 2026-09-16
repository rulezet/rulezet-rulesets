rule TTP_XOR_QUAD_CurrentVersionRun_cfce {
  strings:
    $key_cfce = { 9c a1 [2] b8 af [2] 93 83 [2] bd a1 [2] a9 ba [2] a6 a0 [2] b8 bd [2] ba bc [2] a1 ba [2] bd bd [2] a1 92 }

  condition:
    any of them
}