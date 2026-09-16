rule TTP_XOR_QUAD_CurrentVersionRun_c8c1 {
  strings:
    $key_c8c1 = { 9b ae [2] bf a0 [2] 94 8c [2] ba ae [2] ae b5 [2] a1 af [2] bf b2 [2] bd b3 [2] a6 b5 [2] ba b2 [2] a6 9d }

  condition:
    any of them
}