rule TTP_XOR_QUAD_CurrentVersionRun_55dd {
  strings:
    $key_55dd = { 06 b2 [2] 22 bc [2] 09 90 [2] 27 b2 [2] 33 a9 [2] 3c b3 [2] 22 ae [2] 20 af [2] 3b a9 [2] 27 ae [2] 3b 81 }

  condition:
    any of them
}