rule TTP_XOR_QUAD_CurrentVersionRun_5ac1 {
  strings:
    $key_5ac1 = { 09 ae [2] 2d a0 [2] 06 8c [2] 28 ae [2] 3c b5 [2] 33 af [2] 2d b2 [2] 2f b3 [2] 34 b5 [2] 28 b2 [2] 34 9d }

  condition:
    any of them
}