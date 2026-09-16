rule TTP_XOR_QUAD_CurrentVersionRun_831b {
  strings:
    $key_831b = { d0 74 [2] f4 7a [2] df 56 [2] f1 74 [2] e5 6f [2] ea 75 [2] f4 68 [2] f6 69 [2] ed 6f [2] f1 68 [2] ed 47 }

  condition:
    any of them
}