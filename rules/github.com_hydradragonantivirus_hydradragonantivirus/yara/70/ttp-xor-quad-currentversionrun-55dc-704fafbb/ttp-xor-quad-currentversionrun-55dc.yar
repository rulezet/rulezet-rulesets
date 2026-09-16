rule TTP_XOR_QUAD_CurrentVersionRun_55dc {
  strings:
    $key_55dc = { 06 b3 [2] 22 bd [2] 09 91 [2] 27 b3 [2] 33 a8 [2] 3c b2 [2] 22 af [2] 20 ae [2] 3b a8 [2] 27 af [2] 3b 80 }

  condition:
    any of them
}