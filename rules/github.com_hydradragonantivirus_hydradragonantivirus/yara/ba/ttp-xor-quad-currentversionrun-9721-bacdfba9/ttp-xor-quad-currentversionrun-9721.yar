rule TTP_XOR_QUAD_CurrentVersionRun_9721 {
  strings:
    $key_9721 = { c4 4e [2] e0 40 [2] cb 6c [2] e5 4e [2] f1 55 [2] fe 4f [2] e0 52 [2] e2 53 [2] f9 55 [2] e5 52 [2] f9 7d }

  condition:
    any of them
}