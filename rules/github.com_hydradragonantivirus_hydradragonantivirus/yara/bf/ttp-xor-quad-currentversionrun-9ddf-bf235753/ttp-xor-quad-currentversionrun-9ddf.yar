rule TTP_XOR_QUAD_CurrentVersionRun_9ddf {
  strings:
    $key_9ddf = { ce b0 [2] ea be [2] c1 92 [2] ef b0 [2] fb ab [2] f4 b1 [2] ea ac [2] e8 ad [2] f3 ab [2] ef ac [2] f3 83 }

  condition:
    any of them
}