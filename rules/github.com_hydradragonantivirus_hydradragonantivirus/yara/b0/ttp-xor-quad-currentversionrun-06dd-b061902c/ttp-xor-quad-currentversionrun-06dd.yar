rule TTP_XOR_QUAD_CurrentVersionRun_06dd {
  strings:
    $key_06dd = { 55 b2 [2] 71 bc [2] 5a 90 [2] 74 b2 [2] 60 a9 [2] 6f b3 [2] 71 ae [2] 73 af [2] 68 a9 [2] 74 ae [2] 68 81 }

  condition:
    any of them
}