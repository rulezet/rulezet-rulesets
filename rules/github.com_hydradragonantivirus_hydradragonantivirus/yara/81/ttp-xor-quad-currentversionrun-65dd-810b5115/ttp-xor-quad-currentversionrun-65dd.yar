rule TTP_XOR_QUAD_CurrentVersionRun_65dd {
  strings:
    $key_65dd = { 36 b2 [2] 12 bc [2] 39 90 [2] 17 b2 [2] 03 a9 [2] 0c b3 [2] 12 ae [2] 10 af [2] 0b a9 [2] 17 ae [2] 0b 81 }

  condition:
    any of them
}