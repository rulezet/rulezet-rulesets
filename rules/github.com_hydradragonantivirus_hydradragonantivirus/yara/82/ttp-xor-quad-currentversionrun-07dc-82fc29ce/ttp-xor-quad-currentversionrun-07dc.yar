rule TTP_XOR_QUAD_CurrentVersionRun_07dc {
  strings:
    $key_07dc = { 54 b3 [2] 70 bd [2] 5b 91 [2] 75 b3 [2] 61 a8 [2] 6e b2 [2] 70 af [2] 72 ae [2] 69 a8 [2] 75 af [2] 69 80 }

  condition:
    any of them
}