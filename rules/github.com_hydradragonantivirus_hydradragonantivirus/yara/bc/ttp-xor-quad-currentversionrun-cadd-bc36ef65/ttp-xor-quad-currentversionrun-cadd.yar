rule TTP_XOR_QUAD_CurrentVersionRun_cadd {
  strings:
    $key_cadd = { 99 b2 [2] bd bc [2] 96 90 [2] b8 b2 [2] ac a9 [2] a3 b3 [2] bd ae [2] bf af [2] a4 a9 [2] b8 ae [2] a4 81 }

  condition:
    any of them
}