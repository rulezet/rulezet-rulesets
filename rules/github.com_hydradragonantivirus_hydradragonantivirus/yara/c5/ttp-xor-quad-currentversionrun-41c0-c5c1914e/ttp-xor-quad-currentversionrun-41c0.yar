rule TTP_XOR_QUAD_CurrentVersionRun_41c0 {
  strings:
    $key_41c0 = { 12 af [2] 36 a1 [2] 1d 8d [2] 33 af [2] 27 b4 [2] 28 ae [2] 36 b3 [2] 34 b2 [2] 2f b4 [2] 33 b3 [2] 2f 9c }

  condition:
    any of them
}