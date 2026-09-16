rule TTP_XOR_QUAD_CurrentVersionRun_72dc {
  strings:
    $key_72dc = { 21 b3 [2] 05 bd [2] 2e 91 [2] 00 b3 [2] 14 a8 [2] 1b b2 [2] 05 af [2] 07 ae [2] 1c a8 [2] 00 af [2] 1c 80 }

  condition:
    any of them
}