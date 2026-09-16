rule TTP_XOR_QUAD_CurrentVersionRun_02dc {
  strings:
    $key_02dc = { 51 b3 [2] 75 bd [2] 5e 91 [2] 70 b3 [2] 64 a8 [2] 6b b2 [2] 75 af [2] 77 ae [2] 6c a8 [2] 70 af [2] 6c 80 }

  condition:
    any of them
}