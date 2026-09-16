rule TTP_XOR_QUAD_CurrentVersionRun_51dd {
  strings:
    $key_51dd = { 02 b2 [2] 26 bc [2] 0d 90 [2] 23 b2 [2] 37 a9 [2] 38 b3 [2] 26 ae [2] 24 af [2] 3f a9 [2] 23 ae [2] 3f 81 }

  condition:
    any of them
}