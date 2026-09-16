rule TTP_XOR_QUAD_CurrentVersionRun_e5dc {
  strings:
    $key_e5dc = { b6 b3 [2] 92 bd [2] b9 91 [2] 97 b3 [2] 83 a8 [2] 8c b2 [2] 92 af [2] 90 ae [2] 8b a8 [2] 97 af [2] 8b 80 }

  condition:
    any of them
}