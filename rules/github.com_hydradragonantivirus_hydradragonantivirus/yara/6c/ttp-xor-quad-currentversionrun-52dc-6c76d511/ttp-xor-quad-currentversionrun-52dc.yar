rule TTP_XOR_QUAD_CurrentVersionRun_52dc {
  strings:
    $key_52dc = { 01 b3 [2] 25 bd [2] 0e 91 [2] 20 b3 [2] 34 a8 [2] 3b b2 [2] 25 af [2] 27 ae [2] 3c a8 [2] 20 af [2] 3c 80 }

  condition:
    any of them
}