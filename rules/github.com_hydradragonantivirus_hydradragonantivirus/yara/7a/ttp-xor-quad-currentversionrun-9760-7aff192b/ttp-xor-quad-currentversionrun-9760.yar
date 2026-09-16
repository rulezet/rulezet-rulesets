rule TTP_XOR_QUAD_CurrentVersionRun_9760 {
  strings:
    $key_9760 = { c4 0f [2] e0 01 [2] cb 2d [2] e5 0f [2] f1 14 [2] fe 0e [2] e0 13 [2] e2 12 [2] f9 14 [2] e5 13 [2] f9 3c }

  condition:
    any of them
}