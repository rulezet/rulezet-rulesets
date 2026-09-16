rule TTP_XOR_QUAD_CurrentVersionRun_9edb {
  strings:
    $key_9edb = { cd b4 [2] e9 ba [2] c2 96 [2] ec b4 [2] f8 af [2] f7 b5 [2] e9 a8 [2] eb a9 [2] f0 af [2] ec a8 [2] f0 87 }

  condition:
    any of them
}