rule TTP_XOR_QUAD_CurrentVersionRun_4fdd {
  strings:
    $key_4fdd = { 1c b2 [2] 38 bc [2] 13 90 [2] 3d b2 [2] 29 a9 [2] 26 b3 [2] 38 ae [2] 3a af [2] 21 a9 [2] 3d ae [2] 21 81 }

  condition:
    any of them
}