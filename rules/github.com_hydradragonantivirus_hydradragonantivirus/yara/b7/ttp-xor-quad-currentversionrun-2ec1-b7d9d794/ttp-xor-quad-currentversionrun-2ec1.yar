rule TTP_XOR_QUAD_CurrentVersionRun_2ec1 {
  strings:
    $key_2ec1 = { 7d ae [2] 59 a0 [2] 72 8c [2] 5c ae [2] 48 b5 [2] 47 af [2] 59 b2 [2] 5b b3 [2] 40 b5 [2] 5c b2 [2] 40 9d }

  condition:
    any of them
}