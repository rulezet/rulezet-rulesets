rule TTP_XOR_QUAD_CurrentVersionRun_832e {
  strings:
    $key_832e = { d0 41 [2] f4 4f [2] df 63 [2] f1 41 [2] e5 5a [2] ea 40 [2] f4 5d [2] f6 5c [2] ed 5a [2] f1 5d [2] ed 72 }

  condition:
    any of them
}