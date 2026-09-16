rule TTP_XOR_QUAD_CurrentVersionRun_75cf {
  strings:
    $key_75cf = { 26 a0 [2] 02 ae [2] 29 82 [2] 07 a0 [2] 13 bb [2] 1c a1 [2] 02 bc [2] 00 bd [2] 1b bb [2] 07 bc [2] 1b 93 }

  condition:
    any of them
}