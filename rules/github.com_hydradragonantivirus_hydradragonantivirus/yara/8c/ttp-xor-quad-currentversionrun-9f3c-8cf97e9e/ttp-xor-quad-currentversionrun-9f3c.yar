rule TTP_XOR_QUAD_CurrentVersionRun_9f3c {
  strings:
    $key_9f3c = { cc 53 [2] e8 5d [2] c3 71 [2] ed 53 [2] f9 48 [2] f6 52 [2] e8 4f [2] ea 4e [2] f1 48 [2] ed 4f [2] f1 60 }

  condition:
    any of them
}