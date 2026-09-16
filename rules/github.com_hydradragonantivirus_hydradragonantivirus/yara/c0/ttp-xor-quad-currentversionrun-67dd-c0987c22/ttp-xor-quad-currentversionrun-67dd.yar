rule TTP_XOR_QUAD_CurrentVersionRun_67dd {
  strings:
    $key_67dd = { 34 b2 [2] 10 bc [2] 3b 90 [2] 15 b2 [2] 01 a9 [2] 0e b3 [2] 10 ae [2] 12 af [2] 09 a9 [2] 15 ae [2] 09 81 }

  condition:
    any of them
}