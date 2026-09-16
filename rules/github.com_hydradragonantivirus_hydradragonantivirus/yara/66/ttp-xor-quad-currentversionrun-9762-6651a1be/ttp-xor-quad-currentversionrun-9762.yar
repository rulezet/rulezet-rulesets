rule TTP_XOR_QUAD_CurrentVersionRun_9762 {
  strings:
    $key_9762 = { c4 0d [2] e0 03 [2] cb 2f [2] e5 0d [2] f1 16 [2] fe 0c [2] e0 11 [2] e2 10 [2] f9 16 [2] e5 11 [2] f9 3e }

  condition:
    any of them
}