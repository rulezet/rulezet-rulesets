rule TTP_XOR_QUAD_CurrentVersionRun_833e {
  strings:
    $key_833e = { d0 51 [2] f4 5f [2] df 73 [2] f1 51 [2] e5 4a [2] ea 50 [2] f4 4d [2] f6 4c [2] ed 4a [2] f1 4d [2] ed 62 }

  condition:
    any of them
}