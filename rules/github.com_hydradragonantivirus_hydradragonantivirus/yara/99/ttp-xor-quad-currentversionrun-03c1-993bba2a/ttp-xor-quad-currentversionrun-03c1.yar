rule TTP_XOR_QUAD_CurrentVersionRun_03c1 {
  strings:
    $key_03c1 = { 50 ae [2] 74 a0 [2] 5f 8c [2] 71 ae [2] 65 b5 [2] 6a af [2] 74 b2 [2] 76 b3 [2] 6d b5 [2] 71 b2 [2] 6d 9d }

  condition:
    any of them
}