rule TTP_XOR_QUAD_CurrentVersionRun_843c {
  strings:
    $key_843c = { d7 53 [2] f3 5d [2] d8 71 [2] f6 53 [2] e2 48 [2] ed 52 [2] f3 4f [2] f1 4e [2] ea 48 [2] f6 4f [2] ea 60 }

  condition:
    any of them
}