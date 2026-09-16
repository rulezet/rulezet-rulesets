rule TTP_XOR_QUAD_CurrentVersionRun_835a {
  strings:
    $key_835a = { d0 35 [2] f4 3b [2] df 17 [2] f1 35 [2] e5 2e [2] ea 34 [2] f4 29 [2] f6 28 [2] ed 2e [2] f1 29 [2] ed 06 }

  condition:
    any of them
}