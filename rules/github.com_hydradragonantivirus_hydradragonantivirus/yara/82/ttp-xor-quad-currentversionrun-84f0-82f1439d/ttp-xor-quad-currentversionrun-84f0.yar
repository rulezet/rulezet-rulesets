rule TTP_XOR_QUAD_CurrentVersionRun_84f0 {
  strings:
    $key_84f0 = { d7 9f [2] f3 91 [2] d8 bd [2] f6 9f [2] e2 84 [2] ed 9e [2] f3 83 [2] f1 82 [2] ea 84 [2] f6 83 [2] ea ac }

  condition:
    any of them
}