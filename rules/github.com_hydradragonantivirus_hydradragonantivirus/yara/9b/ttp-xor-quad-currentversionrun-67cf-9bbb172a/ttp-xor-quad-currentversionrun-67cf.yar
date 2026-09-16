rule TTP_XOR_QUAD_CurrentVersionRun_67cf {
  strings:
    $key_67cf = { 34 a0 [2] 10 ae [2] 3b 82 [2] 15 a0 [2] 01 bb [2] 0e a1 [2] 10 bc [2] 12 bd [2] 09 bb [2] 15 bc [2] 09 93 }

  condition:
    any of them
}