rule TTP_XOR_QUAD_CurrentVersionRun_843b {
  strings:
    $key_843b = { d7 54 [2] f3 5a [2] d8 76 [2] f6 54 [2] e2 4f [2] ed 55 [2] f3 48 [2] f1 49 [2] ea 4f [2] f6 48 [2] ea 67 }

  condition:
    any of them
}