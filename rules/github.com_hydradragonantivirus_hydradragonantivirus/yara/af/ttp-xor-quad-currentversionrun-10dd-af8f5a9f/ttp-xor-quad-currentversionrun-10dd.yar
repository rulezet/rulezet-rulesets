rule TTP_XOR_QUAD_CurrentVersionRun_10dd {
  strings:
    $key_10dd = { 43 b2 [2] 67 bc [2] 4c 90 [2] 62 b2 [2] 76 a9 [2] 79 b3 [2] 67 ae [2] 65 af [2] 7e a9 [2] 62 ae [2] 7e 81 }

  condition:
    any of them
}