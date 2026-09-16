rule TTP_XOR_QUAD_CurrentVersionRun_21dc {
  strings:
    $key_21dc = { 72 b3 [2] 56 bd [2] 7d 91 [2] 53 b3 [2] 47 a8 [2] 48 b2 [2] 56 af [2] 54 ae [2] 4f a8 [2] 53 af [2] 4f 80 }

  condition:
    any of them
}