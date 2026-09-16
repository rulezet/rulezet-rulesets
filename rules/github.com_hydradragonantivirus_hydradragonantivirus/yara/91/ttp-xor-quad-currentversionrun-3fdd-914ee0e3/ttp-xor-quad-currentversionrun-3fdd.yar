rule TTP_XOR_QUAD_CurrentVersionRun_3fdd {
  strings:
    $key_3fdd = { 6c b2 [2] 48 bc [2] 63 90 [2] 4d b2 [2] 59 a9 [2] 56 b3 [2] 48 ae [2] 4a af [2] 51 a9 [2] 4d ae [2] 51 81 }

  condition:
    any of them
}