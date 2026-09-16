rule TTP_XOR_QUAD_CurrentVersionRun_d1c1 {
  strings:
    $key_d1c1 = { 82 ae [2] a6 a0 [2] 8d 8c [2] a3 ae [2] b7 b5 [2] b8 af [2] a6 b2 [2] a4 b3 [2] bf b5 [2] a3 b2 [2] bf 9d }

  condition:
    any of them
}