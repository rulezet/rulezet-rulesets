rule TTP_XOR_QUAD_CurrentVersionRun_60cf {
  strings:
    $key_60cf = { 33 a0 [2] 17 ae [2] 3c 82 [2] 12 a0 [2] 06 bb [2] 09 a1 [2] 17 bc [2] 15 bd [2] 0e bb [2] 12 bc [2] 0e 93 }

  condition:
    any of them
}