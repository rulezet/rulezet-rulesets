rule TTP_XOR_QUAD_CurrentVersionRun_9bc0 {
  strings:
    $key_9bc0 = { c8 af [2] ec a1 [2] c7 8d [2] e9 af [2] fd b4 [2] f2 ae [2] ec b3 [2] ee b2 [2] f5 b4 [2] e9 b3 [2] f5 9c }

  condition:
    any of them
}