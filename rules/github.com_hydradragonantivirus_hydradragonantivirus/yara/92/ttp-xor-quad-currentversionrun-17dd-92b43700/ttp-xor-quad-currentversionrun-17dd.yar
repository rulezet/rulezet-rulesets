rule TTP_XOR_QUAD_CurrentVersionRun_17dd {
  strings:
    $key_17dd = { 44 b2 [2] 60 bc [2] 4b 90 [2] 65 b2 [2] 71 a9 [2] 7e b3 [2] 60 ae [2] 62 af [2] 79 a9 [2] 65 ae [2] 79 81 }

  condition:
    any of them
}