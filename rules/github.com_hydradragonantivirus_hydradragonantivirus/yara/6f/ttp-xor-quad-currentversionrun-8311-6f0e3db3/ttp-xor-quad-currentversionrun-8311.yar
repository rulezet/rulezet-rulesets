rule TTP_XOR_QUAD_CurrentVersionRun_8311 {
  strings:
    $key_8311 = { d0 7e [2] f4 70 [2] df 5c [2] f1 7e [2] e5 65 [2] ea 7f [2] f4 62 [2] f6 63 [2] ed 65 [2] f1 62 [2] ed 4d }

  condition:
    any of them
}