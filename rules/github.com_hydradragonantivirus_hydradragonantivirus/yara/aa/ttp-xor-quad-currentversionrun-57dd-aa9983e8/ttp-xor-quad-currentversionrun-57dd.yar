rule TTP_XOR_QUAD_CurrentVersionRun_57dd {
  strings:
    $key_57dd = { 04 b2 [2] 20 bc [2] 0b 90 [2] 25 b2 [2] 31 a9 [2] 3e b3 [2] 20 ae [2] 22 af [2] 39 a9 [2] 25 ae [2] 39 81 }

  condition:
    any of them
}