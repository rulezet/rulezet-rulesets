rule TTP_XOR_QUAD_CurrentVersionRun_45cf {
  strings:
    $key_45cf = { 16 a0 [2] 32 ae [2] 19 82 [2] 37 a0 [2] 23 bb [2] 2c a1 [2] 32 bc [2] 30 bd [2] 2b bb [2] 37 bc [2] 2b 93 }

  condition:
    any of them
}