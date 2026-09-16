rule TTP_XOR_QUAD_CurrentVersionRun_40dc {
  strings:
    $key_40dc = { 13 b3 [2] 37 bd [2] 1c 91 [2] 32 b3 [2] 26 a8 [2] 29 b2 [2] 37 af [2] 35 ae [2] 2e a8 [2] 32 af [2] 2e 80 }

  condition:
    any of them
}