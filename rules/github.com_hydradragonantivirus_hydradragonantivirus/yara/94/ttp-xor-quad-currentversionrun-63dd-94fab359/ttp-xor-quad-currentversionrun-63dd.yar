rule TTP_XOR_QUAD_CurrentVersionRun_63dd {
  strings:
    $key_63dd = { 30 b2 [2] 14 bc [2] 3f 90 [2] 11 b2 [2] 05 a9 [2] 0a b3 [2] 14 ae [2] 16 af [2] 0d a9 [2] 11 ae [2] 0d 81 }

  condition:
    any of them
}