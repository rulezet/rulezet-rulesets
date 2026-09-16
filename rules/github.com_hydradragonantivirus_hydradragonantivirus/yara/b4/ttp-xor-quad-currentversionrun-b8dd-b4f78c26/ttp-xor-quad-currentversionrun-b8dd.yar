rule TTP_XOR_QUAD_CurrentVersionRun_b8dd {
  strings:
    $key_b8dd = { eb b2 [2] cf bc [2] e4 90 [2] ca b2 [2] de a9 [2] d1 b3 [2] cf ae [2] cd af [2] d6 a9 [2] ca ae [2] d6 81 }

  condition:
    any of them
}