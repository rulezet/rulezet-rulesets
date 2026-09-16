rule TTP_XOR_QUAD_CurrentVersionRun_97c4 {
  strings:
    $key_97c4 = { c4 ab [2] e0 a5 [2] cb 89 [2] e5 ab [2] f1 b0 [2] fe aa [2] e0 b7 [2] e2 b6 [2] f9 b0 [2] e5 b7 [2] f9 98 }

  condition:
    any of them
}