rule TTP_XOR_QUAD_CurrentVersionRun_2edd {
  strings:
    $key_2edd = { 7d b2 [2] 59 bc [2] 72 90 [2] 5c b2 [2] 48 a9 [2] 47 b3 [2] 59 ae [2] 5b af [2] 40 a9 [2] 5c ae [2] 40 81 }

  condition:
    any of them
}