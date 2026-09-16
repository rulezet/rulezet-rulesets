rule TTP_XOR_QUAD_CurrentVersionRun_e2dc {
  strings:
    $key_e2dc = { b1 b3 [2] 95 bd [2] be 91 [2] 90 b3 [2] 84 a8 [2] 8b b2 [2] 95 af [2] 97 ae [2] 8c a8 [2] 90 af [2] 8c 80 }

  condition:
    any of them
}