rule TTP_XOR_QUAD_CurrentVersionRun_34dd {
  strings:
    $key_34dd = { 67 b2 [2] 43 bc [2] 68 90 [2] 46 b2 [2] 52 a9 [2] 5d b3 [2] 43 ae [2] 41 af [2] 5a a9 [2] 46 ae [2] 5a 81 }

  condition:
    any of them
}