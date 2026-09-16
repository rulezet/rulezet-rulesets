rule TTP_XOR_QUAD_CurrentVersionRun_51c1 {
  strings:
    $key_51c1 = { 02 ae [2] 26 a0 [2] 0d 8c [2] 23 ae [2] 37 b5 [2] 38 af [2] 26 b2 [2] 24 b3 [2] 3f b5 [2] 23 b2 [2] 3f 9d }

  condition:
    any of them
}