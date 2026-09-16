rule TTP_XOR_QUAD_CurrentVersionRun_56dc {
  strings:
    $key_56dc = { 05 b3 [2] 21 bd [2] 0a 91 [2] 24 b3 [2] 30 a8 [2] 3f b2 [2] 21 af [2] 23 ae [2] 38 a8 [2] 24 af [2] 38 80 }

  condition:
    any of them
}