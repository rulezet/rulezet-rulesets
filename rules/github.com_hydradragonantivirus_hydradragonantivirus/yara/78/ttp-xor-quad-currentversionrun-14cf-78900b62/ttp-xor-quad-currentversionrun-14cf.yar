rule TTP_XOR_QUAD_CurrentVersionRun_14cf {
  strings:
    $key_14cf = { 47 a0 [2] 63 ae [2] 48 82 [2] 66 a0 [2] 72 bb [2] 7d a1 [2] 63 bc [2] 61 bd [2] 7a bb [2] 66 bc [2] 7a 93 }

  condition:
    any of them
}