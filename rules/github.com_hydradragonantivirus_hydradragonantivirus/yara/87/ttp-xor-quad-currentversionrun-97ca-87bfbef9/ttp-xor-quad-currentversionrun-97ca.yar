rule TTP_XOR_QUAD_CurrentVersionRun_97ca {
  strings:
    $key_97ca = { c4 a5 [2] e0 ab [2] cb 87 [2] e5 a5 [2] f1 be [2] fe a4 [2] e0 b9 [2] e2 b8 [2] f9 be [2] e5 b9 [2] f9 96 }

  condition:
    any of them
}