rule TTP_XOR_QUAD_CurrentVersionRun_71dc {
  strings:
    $key_71dc = { 22 b3 [2] 06 bd [2] 2d 91 [2] 03 b3 [2] 17 a8 [2] 18 b2 [2] 06 af [2] 04 ae [2] 1f a8 [2] 03 af [2] 1f 80 }

  condition:
    any of them
}