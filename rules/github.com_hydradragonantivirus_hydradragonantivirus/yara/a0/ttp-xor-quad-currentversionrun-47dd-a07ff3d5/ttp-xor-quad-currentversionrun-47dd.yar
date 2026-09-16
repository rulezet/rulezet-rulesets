rule TTP_XOR_QUAD_CurrentVersionRun_47dd {
  strings:
    $key_47dd = { 14 b2 [2] 30 bc [2] 1b 90 [2] 35 b2 [2] 21 a9 [2] 2e b3 [2] 30 ae [2] 32 af [2] 29 a9 [2] 35 ae [2] 29 81 }

  condition:
    any of them
}