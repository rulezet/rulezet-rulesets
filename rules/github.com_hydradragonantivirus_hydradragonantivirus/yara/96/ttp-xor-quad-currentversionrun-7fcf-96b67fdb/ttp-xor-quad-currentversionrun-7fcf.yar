rule TTP_XOR_QUAD_CurrentVersionRun_7fcf {
  strings:
    $key_7fcf = { 2c a0 [2] 08 ae [2] 23 82 [2] 0d a0 [2] 19 bb [2] 16 a1 [2] 08 bc [2] 0a bd [2] 11 bb [2] 0d bc [2] 11 93 }

  condition:
    any of them
}