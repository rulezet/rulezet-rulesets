rule TTP_XOR_QUAD_CurrentVersionRun_b1dc {
  strings:
    $key_b1dc = { e2 b3 [2] c6 bd [2] ed 91 [2] c3 b3 [2] d7 a8 [2] d8 b2 [2] c6 af [2] c4 ae [2] df a8 [2] c3 af [2] df 80 }

  condition:
    any of them
}