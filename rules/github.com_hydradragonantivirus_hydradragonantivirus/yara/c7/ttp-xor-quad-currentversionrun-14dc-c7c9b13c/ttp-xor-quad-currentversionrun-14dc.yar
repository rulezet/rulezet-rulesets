rule TTP_XOR_QUAD_CurrentVersionRun_14dc {
  strings:
    $key_14dc = { 47 b3 [2] 63 bd [2] 48 91 [2] 66 b3 [2] 72 a8 [2] 7d b2 [2] 63 af [2] 61 ae [2] 7a a8 [2] 66 af [2] 7a 80 }

  condition:
    any of them
}