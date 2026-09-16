rule TTP_XOR_QUAD_CurrentVersionRun_62dd {
  strings:
    $key_62dd = { 31 b2 [2] 15 bc [2] 3e 90 [2] 10 b2 [2] 04 a9 [2] 0b b3 [2] 15 ae [2] 17 af [2] 0c a9 [2] 10 ae [2] 0c 81 }

  condition:
    any of them
}