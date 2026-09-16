rule TTP_XOR_QUAD_CurrentVersionRun_841e {
  strings:
    $key_841e = { d7 71 [2] f3 7f [2] d8 53 [2] f6 71 [2] e2 6a [2] ed 70 [2] f3 6d [2] f1 6c [2] ea 6a [2] f6 6d [2] ea 42 }

  condition:
    any of them
}