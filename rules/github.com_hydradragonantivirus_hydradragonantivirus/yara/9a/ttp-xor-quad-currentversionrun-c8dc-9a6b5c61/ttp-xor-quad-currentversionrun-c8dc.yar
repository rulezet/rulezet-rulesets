rule TTP_XOR_QUAD_CurrentVersionRun_c8dc {
  strings:
    $key_c8dc = { 9b b3 [2] bf bd [2] 94 91 [2] ba b3 [2] ae a8 [2] a1 b2 [2] bf af [2] bd ae [2] a6 a8 [2] ba af [2] a6 80 }

  condition:
    any of them
}