rule TTP_XOR_QUAD_CurrentVersionRun_03cf {
  strings:
    $key_03cf = { 50 a0 [2] 74 ae [2] 5f 82 [2] 71 a0 [2] 65 bb [2] 6a a1 [2] 74 bc [2] 76 bd [2] 6d bb [2] 71 bc [2] 6d 93 }

  condition:
    any of them
}