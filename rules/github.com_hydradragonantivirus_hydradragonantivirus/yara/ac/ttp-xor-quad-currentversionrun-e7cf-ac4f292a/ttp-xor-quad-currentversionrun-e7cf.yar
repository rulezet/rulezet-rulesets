rule TTP_XOR_QUAD_CurrentVersionRun_e7cf {
  strings:
    $key_e7cf = { b4 a0 [2] 90 ae [2] bb 82 [2] 95 a0 [2] 81 bb [2] 8e a1 [2] 90 bc [2] 92 bd [2] 89 bb [2] 95 bc [2] 89 93 }

  condition:
    any of them
}