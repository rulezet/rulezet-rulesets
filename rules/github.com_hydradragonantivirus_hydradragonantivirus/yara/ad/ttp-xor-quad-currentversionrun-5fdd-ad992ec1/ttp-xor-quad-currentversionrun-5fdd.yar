rule TTP_XOR_QUAD_CurrentVersionRun_5fdd {
  strings:
    $key_5fdd = { 0c b2 [2] 28 bc [2] 03 90 [2] 2d b2 [2] 39 a9 [2] 36 b3 [2] 28 ae [2] 2a af [2] 31 a9 [2] 2d ae [2] 31 81 }

  condition:
    any of them
}