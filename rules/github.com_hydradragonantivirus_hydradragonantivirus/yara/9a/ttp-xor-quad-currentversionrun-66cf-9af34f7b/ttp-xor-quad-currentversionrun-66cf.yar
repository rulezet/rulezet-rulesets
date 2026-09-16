rule TTP_XOR_QUAD_CurrentVersionRun_66cf {
  strings:
    $key_66cf = { 35 a0 [2] 11 ae [2] 3a 82 [2] 14 a0 [2] 00 bb [2] 0f a1 [2] 11 bc [2] 13 bd [2] 08 bb [2] 14 bc [2] 08 93 }

  condition:
    any of them
}