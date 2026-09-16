rule TTP_XOR_QUAD_CurrentVersionRun_71cf {
  strings:
    $key_71cf = { 22 a0 [2] 06 ae [2] 2d 82 [2] 03 a0 [2] 17 bb [2] 18 a1 [2] 06 bc [2] 04 bd [2] 1f bb [2] 03 bc [2] 1f 93 }

  condition:
    any of them
}