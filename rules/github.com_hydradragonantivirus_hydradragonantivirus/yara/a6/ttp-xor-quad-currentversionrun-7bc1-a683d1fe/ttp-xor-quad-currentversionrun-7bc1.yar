rule TTP_XOR_QUAD_CurrentVersionRun_7bc1 {
  strings:
    $key_7bc1 = { 28 ae [2] 0c a0 [2] 27 8c [2] 09 ae [2] 1d b5 [2] 12 af [2] 0c b2 [2] 0e b3 [2] 15 b5 [2] 09 b2 [2] 15 9d }

  condition:
    any of them
}