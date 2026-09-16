rule TTP_XOR_QUAD_CurrentVersionRun_9ed6 {
  strings:
    $key_9ed6 = { cd b9 [2] e9 b7 [2] c2 9b [2] ec b9 [2] f8 a2 [2] f7 b8 [2] e9 a5 [2] eb a4 [2] f0 a2 [2] ec a5 [2] f0 8a }

  condition:
    any of them
}