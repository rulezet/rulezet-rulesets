rule TTP_XOR_QUAD_CurrentVersionRun_04cf {
  strings:
    $key_04cf = { 57 a0 [2] 73 ae [2] 58 82 [2] 76 a0 [2] 62 bb [2] 6d a1 [2] 73 bc [2] 71 bd [2] 6a bb [2] 76 bc [2] 6a 93 }

  condition:
    any of them
}