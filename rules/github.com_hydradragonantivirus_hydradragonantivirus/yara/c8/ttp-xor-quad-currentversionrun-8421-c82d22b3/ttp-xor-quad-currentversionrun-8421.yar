rule TTP_XOR_QUAD_CurrentVersionRun_8421 {
  strings:
    $key_8421 = { d7 4e [2] f3 40 [2] d8 6c [2] f6 4e [2] e2 55 [2] ed 4f [2] f3 52 [2] f1 53 [2] ea 55 [2] f6 52 [2] ea 7d }

  condition:
    any of them
}