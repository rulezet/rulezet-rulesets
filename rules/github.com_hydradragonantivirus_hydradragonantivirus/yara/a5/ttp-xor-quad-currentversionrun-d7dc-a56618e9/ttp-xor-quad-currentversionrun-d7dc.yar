rule TTP_XOR_QUAD_CurrentVersionRun_d7dc {
  strings:
    $key_d7dc = { 84 b3 [2] a0 bd [2] 8b 91 [2] a5 b3 [2] b1 a8 [2] be b2 [2] a0 af [2] a2 ae [2] b9 a8 [2] a5 af [2] b9 80 }

  condition:
    any of them
}