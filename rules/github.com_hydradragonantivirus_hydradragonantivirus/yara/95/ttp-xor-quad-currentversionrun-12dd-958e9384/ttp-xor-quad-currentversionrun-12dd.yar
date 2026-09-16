rule TTP_XOR_QUAD_CurrentVersionRun_12dd {
  strings:
    $key_12dd = { 41 b2 [2] 65 bc [2] 4e 90 [2] 60 b2 [2] 74 a9 [2] 7b b3 [2] 65 ae [2] 67 af [2] 7c a9 [2] 60 ae [2] 7c 81 }

  condition:
    any of them
}