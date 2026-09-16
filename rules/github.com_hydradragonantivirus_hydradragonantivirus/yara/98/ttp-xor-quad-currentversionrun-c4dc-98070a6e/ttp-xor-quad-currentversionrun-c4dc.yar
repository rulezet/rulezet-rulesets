rule TTP_XOR_QUAD_CurrentVersionRun_c4dc {
  strings:
    $key_c4dc = { 97 b3 [2] b3 bd [2] 98 91 [2] b6 b3 [2] a2 a8 [2] ad b2 [2] b3 af [2] b1 ae [2] aa a8 [2] b6 af [2] aa 80 }

  condition:
    any of them
}