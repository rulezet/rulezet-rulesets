rule TTP_XOR_QUAD_CurrentVersionRun_9fdc {
  strings:
    $key_9fdc = { cc b3 [2] e8 bd [2] c3 91 [2] ed b3 [2] f9 a8 [2] f6 b2 [2] e8 af [2] ea ae [2] f1 a8 [2] ed af [2] f1 80 }

  condition:
    any of them
}