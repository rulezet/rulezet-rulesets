rule TTP_XOR_QUAD_CurrentVersionRun_c1dc {
  strings:
    $key_c1dc = { 92 b3 [2] b6 bd [2] 9d 91 [2] b3 b3 [2] a7 a8 [2] a8 b2 [2] b6 af [2] b4 ae [2] af a8 [2] b3 af [2] af 80 }

  condition:
    any of them
}