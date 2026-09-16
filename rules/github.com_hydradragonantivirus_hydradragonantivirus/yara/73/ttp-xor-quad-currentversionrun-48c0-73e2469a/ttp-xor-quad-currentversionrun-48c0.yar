rule TTP_XOR_QUAD_CurrentVersionRun_48c0 {
  strings:
    $key_48c0 = { 1b af [2] 3f a1 [2] 14 8d [2] 3a af [2] 2e b4 [2] 21 ae [2] 3f b3 [2] 3d b2 [2] 26 b4 [2] 3a b3 [2] 26 9c }

  condition:
    any of them
}