rule TTP_XOR_QUAD_CurrentVersionRun_22c1 {
  strings:
    $key_22c1 = { 71 ae [2] 55 a0 [2] 7e 8c [2] 50 ae [2] 44 b5 [2] 4b af [2] 55 b2 [2] 57 b3 [2] 4c b5 [2] 50 b2 [2] 4c 9d }

  condition:
    any of them
}