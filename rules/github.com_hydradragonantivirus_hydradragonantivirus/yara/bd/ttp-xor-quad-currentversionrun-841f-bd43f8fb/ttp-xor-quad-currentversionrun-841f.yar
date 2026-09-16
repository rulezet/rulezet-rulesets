rule TTP_XOR_QUAD_CurrentVersionRun_841f {
  strings:
    $key_841f = { d7 70 [2] f3 7e [2] d8 52 [2] f6 70 [2] e2 6b [2] ed 71 [2] f3 6c [2] f1 6d [2] ea 6b [2] f6 6c [2] ea 43 }

  condition:
    any of them
}