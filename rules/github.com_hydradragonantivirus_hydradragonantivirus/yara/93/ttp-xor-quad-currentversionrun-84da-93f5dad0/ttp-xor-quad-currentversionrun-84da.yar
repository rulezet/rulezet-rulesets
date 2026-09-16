rule TTP_XOR_QUAD_CurrentVersionRun_84da {
  strings:
    $key_84da = { d7 b5 [2] f3 bb [2] d8 97 [2] f6 b5 [2] e2 ae [2] ed b4 [2] f3 a9 [2] f1 a8 [2] ea ae [2] f6 a9 [2] ea 86 }

  condition:
    any of them
}