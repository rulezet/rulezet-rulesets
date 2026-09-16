rule TTP_XOR_QUAD_CurrentVersionRun_8314 {
  strings:
    $key_8314 = { d0 7b [2] f4 75 [2] df 59 [2] f1 7b [2] e5 60 [2] ea 7a [2] f4 67 [2] f6 66 [2] ed 60 [2] f1 67 [2] ed 48 }

  condition:
    any of them
}