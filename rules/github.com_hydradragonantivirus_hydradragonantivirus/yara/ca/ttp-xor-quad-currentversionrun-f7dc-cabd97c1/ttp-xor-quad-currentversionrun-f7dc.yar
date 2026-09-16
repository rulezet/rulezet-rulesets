rule TTP_XOR_QUAD_CurrentVersionRun_f7dc {
  strings:
    $key_f7dc = { a4 b3 [2] 80 bd [2] ab 91 [2] 85 b3 [2] 91 a8 [2] 9e b2 [2] 80 af [2] 82 ae [2] 99 a8 [2] 85 af [2] 99 80 }

  condition:
    any of them
}