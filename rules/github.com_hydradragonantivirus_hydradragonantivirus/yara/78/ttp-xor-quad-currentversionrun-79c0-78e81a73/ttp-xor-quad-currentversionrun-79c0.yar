rule TTP_XOR_QUAD_CurrentVersionRun_79c0 {
  strings:
    $key_79c0 = { 2a af [2] 0e a1 [2] 25 8d [2] 0b af [2] 1f b4 [2] 10 ae [2] 0e b3 [2] 0c b2 [2] 17 b4 [2] 0b b3 [2] 17 9c }

  condition:
    any of them
}