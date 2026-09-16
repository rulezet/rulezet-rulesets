rule TTP_XOR_QUAD_CurrentVersionRun_42c1 {
  strings:
    $key_42c1 = { 11 ae [2] 35 a0 [2] 1e 8c [2] 30 ae [2] 24 b5 [2] 2b af [2] 35 b2 [2] 37 b3 [2] 2c b5 [2] 30 b2 [2] 2c 9d }

  condition:
    any of them
}