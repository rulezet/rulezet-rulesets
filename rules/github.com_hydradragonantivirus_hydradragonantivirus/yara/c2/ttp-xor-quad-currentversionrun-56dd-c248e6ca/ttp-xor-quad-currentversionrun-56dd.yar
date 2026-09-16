rule TTP_XOR_QUAD_CurrentVersionRun_56dd {
  strings:
    $key_56dd = { 05 b2 [2] 21 bc [2] 0a 90 [2] 24 b2 [2] 30 a9 [2] 3f b3 [2] 21 ae [2] 23 af [2] 38 a9 [2] 24 ae [2] 38 81 }

  condition:
    any of them
}