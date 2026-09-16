rule TTP_XOR_QUAD_CurrentVersionRun_d1dd {
  strings:
    $key_d1dd = { 82 b2 [2] a6 bc [2] 8d 90 [2] a3 b2 [2] b7 a9 [2] b8 b3 [2] a6 ae [2] a4 af [2] bf a9 [2] a3 ae [2] bf 81 }

  condition:
    any of them
}