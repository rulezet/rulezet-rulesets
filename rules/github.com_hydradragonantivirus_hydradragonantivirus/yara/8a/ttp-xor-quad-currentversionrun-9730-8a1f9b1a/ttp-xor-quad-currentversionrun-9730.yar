rule TTP_XOR_QUAD_CurrentVersionRun_9730 {
  strings:
    $key_9730 = { c4 5f [2] e0 51 [2] cb 7d [2] e5 5f [2] f1 44 [2] fe 5e [2] e0 43 [2] e2 42 [2] f9 44 [2] e5 43 [2] f9 6c }

  condition:
    any of them
}