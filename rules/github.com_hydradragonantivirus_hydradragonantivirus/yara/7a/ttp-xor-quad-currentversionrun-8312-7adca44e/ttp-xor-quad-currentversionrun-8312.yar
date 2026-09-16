rule TTP_XOR_QUAD_CurrentVersionRun_8312 {
  strings:
    $key_8312 = { d0 7d [2] f4 73 [2] df 5f [2] f1 7d [2] e5 66 [2] ea 7c [2] f4 61 [2] f6 60 [2] ed 66 [2] f1 61 [2] ed 4e }

  condition:
    any of them
}