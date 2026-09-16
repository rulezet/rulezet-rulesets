rule TTP_XOR_QUAD_CurrentVersionRun_16dd {
  strings:
    $key_16dd = { 45 b2 [2] 61 bc [2] 4a 90 [2] 64 b2 [2] 70 a9 [2] 7f b3 [2] 61 ae [2] 63 af [2] 78 a9 [2] 64 ae [2] 78 81 }

  condition:
    any of them
}