rule TTP_XOR_QUAD_CurrentVersionRun_04dd {
  strings:
    $key_04dd = { 57 b2 [2] 73 bc [2] 58 90 [2] 76 b2 [2] 62 a9 [2] 6d b3 [2] 73 ae [2] 71 af [2] 6a a9 [2] 76 ae [2] 6a 81 }

  condition:
    any of them
}