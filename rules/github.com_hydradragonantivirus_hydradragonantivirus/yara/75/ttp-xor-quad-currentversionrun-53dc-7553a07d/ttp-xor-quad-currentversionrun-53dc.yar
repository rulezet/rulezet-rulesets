rule TTP_XOR_QUAD_CurrentVersionRun_53dc {
  strings:
    $key_53dc = { 00 b3 [2] 24 bd [2] 0f 91 [2] 21 b3 [2] 35 a8 [2] 3a b2 [2] 24 af [2] 26 ae [2] 3d a8 [2] 21 af [2] 3d 80 }

  condition:
    any of them
}