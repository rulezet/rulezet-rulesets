rule TTP_XOR_QUAD_CurrentVersionRun_77dc {
  strings:
    $key_77dc = { 24 b3 [2] 00 bd [2] 2b 91 [2] 05 b3 [2] 11 a8 [2] 1e b2 [2] 00 af [2] 02 ae [2] 19 a8 [2] 05 af [2] 19 80 }

  condition:
    any of them
}