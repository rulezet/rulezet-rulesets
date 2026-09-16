rule TTP_XOR_QUAD_CurrentVersionRun_57dc {
  strings:
    $key_57dc = { 04 b3 [2] 20 bd [2] 0b 91 [2] 25 b3 [2] 31 a8 [2] 3e b2 [2] 20 af [2] 22 ae [2] 39 a8 [2] 25 af [2] 39 80 }

  condition:
    any of them
}