rule TTP_XOR_QUAD_CurrentVersionRun_846c {
  strings:
    $key_846c = { d7 03 [2] f3 0d [2] d8 21 [2] f6 03 [2] e2 18 [2] ed 02 [2] f3 1f [2] f1 1e [2] ea 18 [2] f6 1f [2] ea 30 }

  condition:
    any of them
}