rule TTP_XOR_QUAD_CurrentVersionRun_d6dc {
  strings:
    $key_d6dc = { 85 b3 [2] a1 bd [2] 8a 91 [2] a4 b3 [2] b0 a8 [2] bf b2 [2] a1 af [2] a3 ae [2] b8 a8 [2] a4 af [2] b8 80 }

  condition:
    any of them
}