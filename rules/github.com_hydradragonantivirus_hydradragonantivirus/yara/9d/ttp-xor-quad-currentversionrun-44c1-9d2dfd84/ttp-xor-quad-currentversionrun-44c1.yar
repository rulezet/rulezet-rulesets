rule TTP_XOR_QUAD_CurrentVersionRun_44c1 {
  strings:
    $key_44c1 = { 17 ae [2] 33 a0 [2] 18 8c [2] 36 ae [2] 22 b5 [2] 2d af [2] 33 b2 [2] 31 b3 [2] 2a b5 [2] 36 b2 [2] 2a 9d }

  condition:
    any of them
}