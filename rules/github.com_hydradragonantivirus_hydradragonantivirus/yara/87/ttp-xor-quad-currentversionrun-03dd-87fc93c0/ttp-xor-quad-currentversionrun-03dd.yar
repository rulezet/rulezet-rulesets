rule TTP_XOR_QUAD_CurrentVersionRun_03dd {
  strings:
    $key_03dd = { 50 b2 [2] 74 bc [2] 5f 90 [2] 71 b2 [2] 65 a9 [2] 6a b3 [2] 74 ae [2] 76 af [2] 6d a9 [2] 71 ae [2] 6d 81 }

  condition:
    any of them
}