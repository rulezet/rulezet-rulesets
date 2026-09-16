rule TTP_XOR_QUAD_CurrentVersionRun_25cf {
  strings:
    $key_25cf = { 76 a0 [2] 52 ae [2] 79 82 [2] 57 a0 [2] 43 bb [2] 4c a1 [2] 52 bc [2] 50 bd [2] 4b bb [2] 57 bc [2] 4b 93 }

  condition:
    any of them
}