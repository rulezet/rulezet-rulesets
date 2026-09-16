rule TTP_XOR_QUAD_CurrentVersionRun_8326 {
  strings:
    $key_8326 = { d0 49 [2] f4 47 [2] df 6b [2] f1 49 [2] e5 52 [2] ea 48 [2] f4 55 [2] f6 54 [2] ed 52 [2] f1 55 [2] ed 7a }

  condition:
    any of them
}