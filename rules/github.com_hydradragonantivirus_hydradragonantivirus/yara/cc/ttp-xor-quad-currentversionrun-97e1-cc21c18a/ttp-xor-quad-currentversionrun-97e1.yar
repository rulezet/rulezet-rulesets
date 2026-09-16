rule TTP_XOR_QUAD_CurrentVersionRun_97e1 {
  strings:
    $key_97e1 = { c4 8e [2] e0 80 [2] cb ac [2] e5 8e [2] f1 95 [2] fe 8f [2] e0 92 [2] e2 93 [2] f9 95 [2] e5 92 [2] f9 bd }

  condition:
    any of them
}