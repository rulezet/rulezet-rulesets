rule TTP_XOR_QUAD_CurrentVersionRun_97e6 {
  strings:
    $key_97e6 = { c4 89 [2] e0 87 [2] cb ab [2] e5 89 [2] f1 92 [2] fe 88 [2] e0 95 [2] e2 94 [2] f9 92 [2] e5 95 [2] f9 ba }

  condition:
    any of them
}