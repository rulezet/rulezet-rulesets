rule TTP_XOR_QUAD_CurrentVersionRun_21dd {
  strings:
    $key_21dd = { 72 b2 [2] 56 bc [2] 7d 90 [2] 53 b2 [2] 47 a9 [2] 48 b3 [2] 56 ae [2] 54 af [2] 4f a9 [2] 53 ae [2] 4f 81 }

  condition:
    any of them
}