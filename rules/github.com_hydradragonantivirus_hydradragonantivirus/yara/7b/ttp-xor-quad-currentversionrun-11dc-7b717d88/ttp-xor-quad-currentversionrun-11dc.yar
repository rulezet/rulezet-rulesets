rule TTP_XOR_QUAD_CurrentVersionRun_11dc {
  strings:
    $key_11dc = { 42 b3 [2] 66 bd [2] 4d 91 [2] 63 b3 [2] 77 a8 [2] 78 b2 [2] 66 af [2] 64 ae [2] 7f a8 [2] 63 af [2] 7f 80 }

  condition:
    any of them
}