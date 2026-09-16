rule TTP_XOR_QUAD_CurrentVersionRun_44c0 {
  strings:
    $key_44c0 = { 17 af [2] 33 a1 [2] 18 8d [2] 36 af [2] 22 b4 [2] 2d ae [2] 33 b3 [2] 31 b2 [2] 2a b4 [2] 36 b3 [2] 2a 9c }

  condition:
    any of them
}