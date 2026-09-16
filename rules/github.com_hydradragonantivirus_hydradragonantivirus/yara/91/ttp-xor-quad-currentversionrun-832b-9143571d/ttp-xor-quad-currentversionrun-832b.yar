rule TTP_XOR_QUAD_CurrentVersionRun_832b {
  strings:
    $key_832b = { d0 44 [2] f4 4a [2] df 66 [2] f1 44 [2] e5 5f [2] ea 45 [2] f4 58 [2] f6 59 [2] ed 5f [2] f1 58 [2] ed 77 }

  condition:
    any of them
}