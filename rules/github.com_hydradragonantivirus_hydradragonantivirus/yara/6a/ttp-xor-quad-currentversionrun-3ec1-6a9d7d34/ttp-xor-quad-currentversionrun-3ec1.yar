rule TTP_XOR_QUAD_CurrentVersionRun_3ec1 {
  strings:
    $key_3ec1 = { 6d ae [2] 49 a0 [2] 62 8c [2] 4c ae [2] 58 b5 [2] 57 af [2] 49 b2 [2] 4b b3 [2] 50 b5 [2] 4c b2 [2] 50 9d }

  condition:
    any of them
}