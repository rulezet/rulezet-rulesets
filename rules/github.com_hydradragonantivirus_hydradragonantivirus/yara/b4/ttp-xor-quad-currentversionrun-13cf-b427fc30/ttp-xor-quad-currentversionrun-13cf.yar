rule TTP_XOR_QUAD_CurrentVersionRun_13cf {
  strings:
    $key_13cf = { 40 a0 [2] 64 ae [2] 4f 82 [2] 61 a0 [2] 75 bb [2] 7a a1 [2] 64 bc [2] 66 bd [2] 7d bb [2] 61 bc [2] 7d 93 }

  condition:
    any of them
}