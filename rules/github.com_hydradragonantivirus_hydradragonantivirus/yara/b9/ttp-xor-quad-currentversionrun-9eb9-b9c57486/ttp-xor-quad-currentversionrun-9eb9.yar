rule TTP_XOR_QUAD_CurrentVersionRun_9eb9 {
  strings:
    $key_9eb9 = { cd d6 [2] e9 d8 [2] c2 f4 [2] ec d6 [2] f8 cd [2] f7 d7 [2] e9 ca [2] eb cb [2] f0 cd [2] ec ca [2] f0 e5 }

  condition:
    any of them
}