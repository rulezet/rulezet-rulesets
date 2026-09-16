rule TTP_XOR_QUAD_CurrentVersionRun_79cf {
  strings:
    $key_79cf = { 2a a0 [2] 0e ae [2] 25 82 [2] 0b a0 [2] 1f bb [2] 10 a1 [2] 0e bc [2] 0c bd [2] 17 bb [2] 0b bc [2] 17 93 }

  condition:
    any of them
}