rule TTP_XOR_QUAD_CurrentVersionRun_833c {
  strings:
    $key_833c = { d0 53 [2] f4 5d [2] df 71 [2] f1 53 [2] e5 48 [2] ea 52 [2] f4 4f [2] f6 4e [2] ed 48 [2] f1 4f [2] ed 60 }

  condition:
    any of them
}