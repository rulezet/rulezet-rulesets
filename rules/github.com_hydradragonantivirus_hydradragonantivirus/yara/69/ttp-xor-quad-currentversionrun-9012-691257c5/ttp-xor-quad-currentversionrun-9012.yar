rule TTP_XOR_QUAD_CurrentVersionRun_9012 {
  strings:
    $key_9012 = { c3 7d [2] e7 73 [2] cc 5f [2] e2 7d [2] f6 66 [2] f9 7c [2] e7 61 [2] e5 60 [2] fe 66 [2] e2 61 [2] fe 4e }

  condition:
    any of them
}