rule TTP_XOR_QUAD_CurrentVersionRun_75dc {
  strings:
    $key_75dc = { 26 b3 [2] 02 bd [2] 29 91 [2] 07 b3 [2] 13 a8 [2] 1c b2 [2] 02 af [2] 00 ae [2] 1b a8 [2] 07 af [2] 1b 80 }

  condition:
    any of them
}