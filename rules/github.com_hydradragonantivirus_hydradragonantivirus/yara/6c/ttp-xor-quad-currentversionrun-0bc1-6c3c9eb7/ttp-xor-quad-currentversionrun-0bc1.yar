rule TTP_XOR_QUAD_CurrentVersionRun_0bc1 {
  strings:
    $key_0bc1 = { 58 ae [2] 7c a0 [2] 57 8c [2] 79 ae [2] 6d b5 [2] 62 af [2] 7c b2 [2] 7e b3 [2] 65 b5 [2] 79 b2 [2] 65 9d }

  condition:
    any of them
}