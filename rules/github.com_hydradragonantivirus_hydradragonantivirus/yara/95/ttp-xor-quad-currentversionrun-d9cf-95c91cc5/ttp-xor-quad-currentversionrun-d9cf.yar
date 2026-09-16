rule TTP_XOR_QUAD_CurrentVersionRun_d9cf {
  strings:
    $key_d9cf = { 8a a0 [2] ae ae [2] 85 82 [2] ab a0 [2] bf bb [2] b0 a1 [2] ae bc [2] ac bd [2] b7 bb [2] ab bc [2] b7 93 }

  condition:
    any of them
}