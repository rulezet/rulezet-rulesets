rule TTP_XOR_QUAD_CurrentVersionRun_830c {
  strings:
    $key_830c = { d0 63 [2] f4 6d [2] df 41 [2] f1 63 [2] e5 78 [2] ea 62 [2] f4 7f [2] f6 7e [2] ed 78 [2] f1 7f [2] ed 50 }

  condition:
    any of them
}