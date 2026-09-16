rule TTP_XOR_QUAD_CurrentVersionRun_9fc0 {
  strings:
    $key_9fc0 = { cc af [2] e8 a1 [2] c3 8d [2] ed af [2] f9 b4 [2] f6 ae [2] e8 b3 [2] ea b2 [2] f1 b4 [2] ed b3 [2] f1 9c }

  condition:
    any of them
}