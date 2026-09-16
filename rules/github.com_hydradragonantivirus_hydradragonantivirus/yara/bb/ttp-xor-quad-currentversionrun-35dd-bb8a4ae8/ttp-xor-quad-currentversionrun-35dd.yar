rule TTP_XOR_QUAD_CurrentVersionRun_35dd {
  strings:
    $key_35dd = { 66 b2 [2] 42 bc [2] 69 90 [2] 47 b2 [2] 53 a9 [2] 5c b3 [2] 42 ae [2] 40 af [2] 5b a9 [2] 47 ae [2] 5b 81 }

  condition:
    any of them
}