rule TTP_XOR_QUAD_CurrentVersionRun_4bc1 {
  strings:
    $key_4bc1 = { 18 ae [2] 3c a0 [2] 17 8c [2] 39 ae [2] 2d b5 [2] 22 af [2] 3c b2 [2] 3e b3 [2] 25 b5 [2] 39 b2 [2] 25 9d }

  condition:
    any of them
}