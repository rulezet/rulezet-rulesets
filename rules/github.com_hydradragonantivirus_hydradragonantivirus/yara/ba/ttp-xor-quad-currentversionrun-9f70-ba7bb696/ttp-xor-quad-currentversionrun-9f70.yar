rule TTP_XOR_QUAD_CurrentVersionRun_9f70 {
  strings:
    $key_9f70 = { cc 1f [2] e8 11 [2] c3 3d [2] ed 1f [2] f9 04 [2] f6 1e [2] e8 03 [2] ea 02 [2] f1 04 [2] ed 03 [2] f1 2c }

  condition:
    any of them
}