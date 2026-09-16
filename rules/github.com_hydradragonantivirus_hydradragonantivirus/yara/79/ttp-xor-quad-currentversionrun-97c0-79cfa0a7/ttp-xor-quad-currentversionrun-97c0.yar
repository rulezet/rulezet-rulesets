rule TTP_XOR_QUAD_CurrentVersionRun_97c0 {
  strings:
    $key_97c0 = { c4 af [2] e0 a1 [2] cb 8d [2] e5 af [2] f1 b4 [2] fe ae [2] e0 b3 [2] e2 b2 [2] f9 b4 [2] e5 b3 [2] f9 9c }

  condition:
    any of them
}