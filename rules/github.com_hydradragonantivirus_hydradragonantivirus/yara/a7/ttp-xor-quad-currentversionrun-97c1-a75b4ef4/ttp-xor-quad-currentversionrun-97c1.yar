rule TTP_XOR_QUAD_CurrentVersionRun_97c1 {
  strings:
    $key_97c1 = { c4 ae [2] e0 a0 [2] cb 8c [2] e5 ae [2] f1 b5 [2] fe af [2] e0 b2 [2] e2 b3 [2] f9 b5 [2] e5 b2 [2] f9 9d }

  condition:
    any of them
}