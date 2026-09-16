rule TTP_XOR_QUAD_CurrentVersionRun_22dc {
  strings:
    $key_22dc = { 71 b3 [2] 55 bd [2] 7e 91 [2] 50 b3 [2] 44 a8 [2] 4b b2 [2] 55 af [2] 57 ae [2] 4c a8 [2] 50 af [2] 4c 80 }

  condition:
    any of them
}