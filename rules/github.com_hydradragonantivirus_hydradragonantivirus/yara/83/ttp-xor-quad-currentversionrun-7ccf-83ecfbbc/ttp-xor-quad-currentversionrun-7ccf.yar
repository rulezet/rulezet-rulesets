rule TTP_XOR_QUAD_CurrentVersionRun_7ccf {
  strings:
    $key_7ccf = { 2f a0 [2] 0b ae [2] 20 82 [2] 0e a0 [2] 1a bb [2] 15 a1 [2] 0b bc [2] 09 bd [2] 12 bb [2] 0e bc [2] 12 93 }

  condition:
    any of them
}