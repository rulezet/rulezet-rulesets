rule TTP_XOR_QUAD_CurrentVersionRun_f4c1 {
  strings:
    $key_f4c1 = { a7 ae [2] 83 a0 [2] a8 8c [2] 86 ae [2] 92 b5 [2] 9d af [2] 83 b2 [2] 81 b3 [2] 9a b5 [2] 86 b2 [2] 9a 9d }

  condition:
    any of them
}