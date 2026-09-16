rule TTP_XOR_QUAD_CurrentVersionRun_51c0 {
  strings:
    $key_51c0 = { 02 af [2] 26 a1 [2] 0d 8d [2] 23 af [2] 37 b4 [2] 38 ae [2] 26 b3 [2] 24 b2 [2] 3f b4 [2] 23 b3 [2] 3f 9c }

  condition:
    any of them
}