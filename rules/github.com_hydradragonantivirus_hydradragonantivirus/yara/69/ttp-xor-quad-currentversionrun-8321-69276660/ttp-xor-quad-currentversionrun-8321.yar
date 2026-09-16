rule TTP_XOR_QUAD_CurrentVersionRun_8321 {
  strings:
    $key_8321 = { d0 4e [2] f4 40 [2] df 6c [2] f1 4e [2] e5 55 [2] ea 4f [2] f4 52 [2] f6 53 [2] ed 55 [2] f1 52 [2] ed 7d }

  condition:
    any of them
}