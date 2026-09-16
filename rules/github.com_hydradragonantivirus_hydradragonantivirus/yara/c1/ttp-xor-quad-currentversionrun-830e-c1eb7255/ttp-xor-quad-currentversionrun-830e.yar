rule TTP_XOR_QUAD_CurrentVersionRun_830e {
  strings:
    $key_830e = { d0 61 [2] f4 6f [2] df 43 [2] f1 61 [2] e5 7a [2] ea 60 [2] f4 7d [2] f6 7c [2] ed 7a [2] f1 7d [2] ed 52 }

  condition:
    any of them
}