rule TTP_XOR_QUAD_CurrentVersionRun_95c0 {
  strings:
    $key_95c0 = { c6 af [2] e2 a1 [2] c9 8d [2] e7 af [2] f3 b4 [2] fc ae [2] e2 b3 [2] e0 b2 [2] fb b4 [2] e7 b3 [2] fb 9c }

  condition:
    any of them
}