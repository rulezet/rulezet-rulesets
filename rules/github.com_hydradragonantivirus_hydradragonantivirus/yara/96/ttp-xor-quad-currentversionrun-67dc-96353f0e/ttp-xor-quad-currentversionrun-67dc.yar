rule TTP_XOR_QUAD_CurrentVersionRun_67dc {
  strings:
    $key_67dc = { 34 b3 [2] 10 bd [2] 3b 91 [2] 15 b3 [2] 01 a8 [2] 0e b2 [2] 10 af [2] 12 ae [2] 09 a8 [2] 15 af [2] 09 80 }

  condition:
    any of them
}