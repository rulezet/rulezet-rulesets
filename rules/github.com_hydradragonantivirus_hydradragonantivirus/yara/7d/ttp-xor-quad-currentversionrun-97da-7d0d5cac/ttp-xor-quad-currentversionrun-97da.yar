rule TTP_XOR_QUAD_CurrentVersionRun_97da {
  strings:
    $key_97da = { c4 b5 [2] e0 bb [2] cb 97 [2] e5 b5 [2] f1 ae [2] fe b4 [2] e0 a9 [2] e2 a8 [2] f9 ae [2] e5 a9 [2] f9 86 }

  condition:
    any of them
}