rule TTP_XOR_QUAD_CurrentVersionRun_0fdd {
  strings:
    $key_0fdd = { 5c b2 [2] 78 bc [2] 53 90 [2] 7d b2 [2] 69 a9 [2] 66 b3 [2] 78 ae [2] 7a af [2] 61 a9 [2] 7d ae [2] 61 81 }

  condition:
    any of them
}