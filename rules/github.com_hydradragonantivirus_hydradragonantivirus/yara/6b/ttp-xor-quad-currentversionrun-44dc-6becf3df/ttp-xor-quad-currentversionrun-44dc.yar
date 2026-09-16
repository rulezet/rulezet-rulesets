rule TTP_XOR_QUAD_CurrentVersionRun_44dc {
  strings:
    $key_44dc = { 17 b3 [2] 33 bd [2] 18 91 [2] 36 b3 [2] 22 a8 [2] 2d b2 [2] 33 af [2] 31 ae [2] 2a a8 [2] 36 af [2] 2a 80 }

  condition:
    any of them
}