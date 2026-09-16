rule TTP_XOR_QUAD_CurrentVersionRun_50dd {
  strings:
    $key_50dd = { 03 b2 [2] 27 bc [2] 0c 90 [2] 22 b2 [2] 36 a9 [2] 39 b3 [2] 27 ae [2] 25 af [2] 3e a9 [2] 22 ae [2] 3e 81 }

  condition:
    any of them
}