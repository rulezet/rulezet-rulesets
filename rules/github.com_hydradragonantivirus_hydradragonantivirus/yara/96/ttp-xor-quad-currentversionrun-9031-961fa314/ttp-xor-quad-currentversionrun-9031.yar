rule TTP_XOR_QUAD_CurrentVersionRun_9031 {
  strings:
    $key_9031 = { c3 5e [2] e7 50 [2] cc 7c [2] e2 5e [2] f6 45 [2] f9 5f [2] e7 42 [2] e5 43 [2] fe 45 [2] e2 42 [2] fe 6d }

  condition:
    any of them
}