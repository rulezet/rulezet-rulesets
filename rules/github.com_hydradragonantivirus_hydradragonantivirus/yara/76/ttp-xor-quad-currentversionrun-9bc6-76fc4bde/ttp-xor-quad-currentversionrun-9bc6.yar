rule TTP_XOR_QUAD_CurrentVersionRun_9bc6 {
  strings:
    $key_9bc6 = { c8 a9 [2] ec a7 [2] c7 8b [2] e9 a9 [2] fd b2 [2] f2 a8 [2] ec b5 [2] ee b4 [2] f5 b2 [2] e9 b5 [2] f5 9a }

  condition:
    any of them
}