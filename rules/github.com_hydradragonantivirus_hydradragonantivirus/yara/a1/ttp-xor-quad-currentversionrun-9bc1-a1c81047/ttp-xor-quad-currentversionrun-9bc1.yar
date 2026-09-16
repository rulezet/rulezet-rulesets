rule TTP_XOR_QUAD_CurrentVersionRun_9bc1 {
  strings:
    $key_9bc1 = { c8 ae [2] ec a0 [2] c7 8c [2] e9 ae [2] fd b5 [2] f2 af [2] ec b2 [2] ee b3 [2] f5 b5 [2] e9 b2 [2] f5 9d }

  condition:
    any of them
}