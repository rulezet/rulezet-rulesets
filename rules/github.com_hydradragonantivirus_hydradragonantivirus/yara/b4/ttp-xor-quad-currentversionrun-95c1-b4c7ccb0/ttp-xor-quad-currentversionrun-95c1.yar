rule TTP_XOR_QUAD_CurrentVersionRun_95c1 {
  strings:
    $key_95c1 = { c6 ae [2] e2 a0 [2] c9 8c [2] e7 ae [2] f3 b5 [2] fc af [2] e2 b2 [2] e0 b3 [2] fb b5 [2] e7 b2 [2] fb 9d }

  condition:
    any of them
}