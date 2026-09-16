rule TTP_XOR_QUAD_CurrentVersionRun_8302 {
  strings:
    $key_8302 = { d0 6d [2] f4 63 [2] df 4f [2] f1 6d [2] e5 76 [2] ea 6c [2] f4 71 [2] f6 70 [2] ed 76 [2] f1 71 [2] ed 5e }

  condition:
    any of them
}