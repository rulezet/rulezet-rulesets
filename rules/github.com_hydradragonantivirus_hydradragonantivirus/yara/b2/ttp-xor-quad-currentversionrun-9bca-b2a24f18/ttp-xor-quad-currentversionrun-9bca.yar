rule TTP_XOR_QUAD_CurrentVersionRun_9bca {
  strings:
    $key_9bca = { c8 a5 [2] ec ab [2] c7 87 [2] e9 a5 [2] fd be [2] f2 a4 [2] ec b9 [2] ee b8 [2] f5 be [2] e9 b9 [2] f5 96 }

  condition:
    any of them
}