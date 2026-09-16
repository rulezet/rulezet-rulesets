rule TTP_XOR_QUAD_CurrentVersionRun_4fc0 {
  strings:
    $key_4fc0 = { 1c af [2] 38 a1 [2] 13 8d [2] 3d af [2] 29 b4 [2] 26 ae [2] 38 b3 [2] 3a b2 [2] 21 b4 [2] 3d b3 [2] 21 9c }

  condition:
    any of them
}