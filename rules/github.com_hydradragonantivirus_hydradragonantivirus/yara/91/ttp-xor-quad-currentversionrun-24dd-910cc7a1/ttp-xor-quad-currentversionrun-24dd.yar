rule TTP_XOR_QUAD_CurrentVersionRun_24dd {
  strings:
    $key_24dd = { 77 b2 [2] 53 bc [2] 78 90 [2] 56 b2 [2] 42 a9 [2] 4d b3 [2] 53 ae [2] 51 af [2] 4a a9 [2] 56 ae [2] 4a 81 }

  condition:
    any of them
}