rule TTP_XOR_QUAD_CurrentVersionRun_cac1 {
  strings:
    $key_cac1 = { 99 ae [2] bd a0 [2] 96 8c [2] b8 ae [2] ac b5 [2] a3 af [2] bd b2 [2] bf b3 [2] a4 b5 [2] b8 b2 [2] a4 9d }

  condition:
    any of them
}