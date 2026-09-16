rule TTP_XOR_QUAD_CurrentVersionRun_b6dc {
  strings:
    $key_b6dc = { e5 b3 [2] c1 bd [2] ea 91 [2] c4 b3 [2] d0 a8 [2] df b2 [2] c1 af [2] c3 ae [2] d8 a8 [2] c4 af [2] d8 80 }

  condition:
    any of them
}