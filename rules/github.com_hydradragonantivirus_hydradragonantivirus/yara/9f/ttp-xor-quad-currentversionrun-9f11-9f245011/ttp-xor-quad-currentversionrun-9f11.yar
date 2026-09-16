rule TTP_XOR_QUAD_CurrentVersionRun_9f11 {
  strings:
    $key_9f11 = { cc 7e [2] e8 70 [2] c3 5c [2] ed 7e [2] f9 65 [2] f6 7f [2] e8 62 [2] ea 63 [2] f1 65 [2] ed 62 [2] f1 4d }

  condition:
    any of them
}