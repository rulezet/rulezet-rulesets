rule TTP_XOR_QUAD_CurrentVersionRun_840e {
  strings:
    $key_840e = { d7 61 [2] f3 6f [2] d8 43 [2] f6 61 [2] e2 7a [2] ed 60 [2] f3 7d [2] f1 7c [2] ea 7a [2] f6 7d [2] ea 52 }

  condition:
    any of them
}