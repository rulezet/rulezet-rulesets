rule TTP_XOR_QUAD_CurrentVersionRun_c8cf {
  strings:
    $key_c8cf = { 9b a0 [2] bf ae [2] 94 82 [2] ba a0 [2] ae bb [2] a1 a1 [2] bf bc [2] bd bd [2] a6 bb [2] ba bc [2] a6 93 }

  condition:
    any of them
}