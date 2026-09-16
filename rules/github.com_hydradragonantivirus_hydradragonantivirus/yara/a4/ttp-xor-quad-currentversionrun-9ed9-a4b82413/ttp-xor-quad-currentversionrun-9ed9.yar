rule TTP_XOR_QUAD_CurrentVersionRun_9ed9 {
  strings:
    $key_9ed9 = { cd b6 [2] e9 b8 [2] c2 94 [2] ec b6 [2] f8 ad [2] f7 b7 [2] e9 aa [2] eb ab [2] f0 ad [2] ec aa [2] f0 85 }

  condition:
    any of them
}