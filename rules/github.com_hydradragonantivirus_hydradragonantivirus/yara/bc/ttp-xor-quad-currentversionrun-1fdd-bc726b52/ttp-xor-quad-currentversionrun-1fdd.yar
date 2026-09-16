rule TTP_XOR_QUAD_CurrentVersionRun_1fdd {
  strings:
    $key_1fdd = { 4c b2 [2] 68 bc [2] 43 90 [2] 6d b2 [2] 79 a9 [2] 76 b3 [2] 68 ae [2] 6a af [2] 71 a9 [2] 6d ae [2] 71 81 }

  condition:
    any of them
}