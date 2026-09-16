rule TTP_XOR_QUAD_CurrentVersionRun_f5dd {
  strings:
    $key_f5dd = { a6 b2 [2] 82 bc [2] a9 90 [2] 87 b2 [2] 93 a9 [2] 9c b3 [2] 82 ae [2] 80 af [2] 9b a9 [2] 87 ae [2] 9b 81 }

  condition:
    any of them
}