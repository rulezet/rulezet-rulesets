rule TTP_XOR_QUAD_CurrentVersionRun_77cf {
  strings:
    $key_77cf = { 24 a0 [2] 00 ae [2] 2b 82 [2] 05 a0 [2] 11 bb [2] 1e a1 [2] 00 bc [2] 02 bd [2] 19 bb [2] 05 bc [2] 19 93 }

  condition:
    any of them
}