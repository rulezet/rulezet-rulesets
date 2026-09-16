rule TTP_XOR_QUAD_CurrentVersionRun_01dd {
  strings:
    $key_01dd = { 52 b2 [2] 76 bc [2] 5d 90 [2] 73 b2 [2] 67 a9 [2] 68 b3 [2] 76 ae [2] 74 af [2] 6f a9 [2] 73 ae [2] 6f 81 }

  condition:
    any of them
}