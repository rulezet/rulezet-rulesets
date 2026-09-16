rule TTP_XOR_QUAD_CurrentVersionRun_53cf {
  strings:
    $key_53cf = { 00 a0 [2] 24 ae [2] 0f 82 [2] 21 a0 [2] 35 bb [2] 3a a1 [2] 24 bc [2] 26 bd [2] 3d bb [2] 21 bc [2] 3d 93 }

  condition:
    any of them
}