rule TTP_XOR_QUAD_CurrentVersionRun_2ac1 {
  strings:
    $key_2ac1 = { 79 ae [2] 5d a0 [2] 76 8c [2] 58 ae [2] 4c b5 [2] 43 af [2] 5d b2 [2] 5f b3 [2] 44 b5 [2] 58 b2 [2] 44 9d }

  condition:
    any of them
}