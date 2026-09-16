rule TTP_XOR_QUAD_CurrentVersionRun_69c0 {
  strings:
    $key_69c0 = { 3a af [2] 1e a1 [2] 35 8d [2] 1b af [2] 0f b4 [2] 00 ae [2] 1e b3 [2] 1c b2 [2] 07 b4 [2] 1b b3 [2] 07 9c }

  condition:
    any of them
}