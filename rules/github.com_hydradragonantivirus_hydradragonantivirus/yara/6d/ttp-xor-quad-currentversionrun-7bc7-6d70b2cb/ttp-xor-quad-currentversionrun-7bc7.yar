rule TTP_XOR_QUAD_CurrentVersionRun_7bc7 {
  strings:
    $key_7bc7 = { 28 a8 [2] 0c a6 [2] 27 8a [2] 09 a8 [2] 1d b3 [2] 12 a9 [2] 0c b4 [2] 0e b5 [2] 15 b3 [2] 09 b4 [2] 15 9b }

  condition:
    any of them
}