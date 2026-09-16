rule TTP_XOR_QUAD_CurrentVersionRun_41dc {
  strings:
    $key_41dc = { 12 b3 [2] 36 bd [2] 1d 91 [2] 33 b3 [2] 27 a8 [2] 28 b2 [2] 36 af [2] 34 ae [2] 2f a8 [2] 33 af [2] 2f 80 }

  condition:
    any of them
}