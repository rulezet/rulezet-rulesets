rule TTP_XOR_QUAD_CurrentVersionRun_9bd9 {
  strings:
    $key_9bd9 = { c8 b6 [2] ec b8 [2] c7 94 [2] e9 b6 [2] fd ad [2] f2 b7 [2] ec aa [2] ee ab [2] f5 ad [2] e9 aa [2] f5 85 }

  condition:
    any of them
}