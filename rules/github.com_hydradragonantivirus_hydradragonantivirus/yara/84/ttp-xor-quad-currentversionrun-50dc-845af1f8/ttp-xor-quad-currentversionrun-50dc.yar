rule TTP_XOR_QUAD_CurrentVersionRun_50dc {
  strings:
    $key_50dc = { 03 b3 [2] 27 bd [2] 0c 91 [2] 22 b3 [2] 36 a8 [2] 39 b2 [2] 27 af [2] 25 ae [2] 3e a8 [2] 22 af [2] 3e 80 }

  condition:
    any of them
}