rule TTP_XOR_QUAD_CurrentVersionRun_7bc4 {
  strings:
    $key_7bc4 = { 28 ab [2] 0c a5 [2] 27 89 [2] 09 ab [2] 1d b0 [2] 12 aa [2] 0c b7 [2] 0e b6 [2] 15 b0 [2] 09 b7 [2] 15 98 }

  condition:
    any of them
}