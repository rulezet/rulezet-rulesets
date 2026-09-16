rule TTP_XOR_QUAD_CurrentVersionRun_83da {
  strings:
    $key_83da = { d0 b5 [2] f4 bb [2] df 97 [2] f1 b5 [2] e5 ae [2] ea b4 [2] f4 a9 [2] f6 a8 [2] ed ae [2] f1 a9 [2] ed 86 }

  condition:
    any of them
}