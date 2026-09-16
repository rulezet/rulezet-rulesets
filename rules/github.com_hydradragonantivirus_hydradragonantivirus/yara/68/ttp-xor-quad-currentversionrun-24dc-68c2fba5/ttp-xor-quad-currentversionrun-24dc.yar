rule TTP_XOR_QUAD_CurrentVersionRun_24dc {
  strings:
    $key_24dc = { 77 b3 [2] 53 bd [2] 78 91 [2] 56 b3 [2] 42 a8 [2] 4d b2 [2] 53 af [2] 51 ae [2] 4a a8 [2] 56 af [2] 4a 80 }

  condition:
    any of them
}