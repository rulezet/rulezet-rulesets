rule TTP_XOR_QUAD_CurrentVersionRun_1fcf {
  strings:
    $key_1fcf = { 4c a0 [2] 68 ae [2] 43 82 [2] 6d a0 [2] 79 bb [2] 76 a1 [2] 68 bc [2] 6a bd [2] 71 bb [2] 6d bc [2] 71 93 }

  condition:
    any of them
}