rule TTP_XOR_QUAD_CurrentVersionRun_c2dc {
  strings:
    $key_c2dc = { 91 b3 [2] b5 bd [2] 9e 91 [2] b0 b3 [2] a4 a8 [2] ab b2 [2] b5 af [2] b7 ae [2] ac a8 [2] b0 af [2] ac 80 }

  condition:
    any of them
}