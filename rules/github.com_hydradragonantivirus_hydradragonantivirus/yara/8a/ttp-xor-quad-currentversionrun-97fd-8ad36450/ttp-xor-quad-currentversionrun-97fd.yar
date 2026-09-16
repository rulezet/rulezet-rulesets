rule TTP_XOR_QUAD_CurrentVersionRun_97fd {
  strings:
    $key_97fd = { c4 92 [2] e0 9c [2] cb b0 [2] e5 92 [2] f1 89 [2] fe 93 [2] e0 8e [2] e2 8f [2] f9 89 [2] e5 8e [2] f9 a1 }

  condition:
    any of them
}