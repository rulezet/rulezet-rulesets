rule TTP_XOR_QUAD_CurrentVersionRun_8476 {
  strings:
    $key_8476 = { d7 19 [2] f3 17 [2] d8 3b [2] f6 19 [2] e2 02 [2] ed 18 [2] f3 05 [2] f1 04 [2] ea 02 [2] f6 05 [2] ea 2a }

  condition:
    any of them
}