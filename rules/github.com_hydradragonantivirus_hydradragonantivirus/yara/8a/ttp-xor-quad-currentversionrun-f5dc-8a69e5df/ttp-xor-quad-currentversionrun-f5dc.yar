rule TTP_XOR_QUAD_CurrentVersionRun_f5dc {
  strings:
    $key_f5dc = { a6 b3 [2] 82 bd [2] a9 91 [2] 87 b3 [2] 93 a8 [2] 9c b2 [2] 82 af [2] 80 ae [2] 9b a8 [2] 87 af [2] 9b 80 }

  condition:
    any of them
}