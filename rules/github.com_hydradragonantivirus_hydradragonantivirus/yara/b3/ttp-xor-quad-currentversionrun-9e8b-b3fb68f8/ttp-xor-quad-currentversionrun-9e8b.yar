rule TTP_XOR_QUAD_CurrentVersionRun_9e8b {
  strings:
    $key_9e8b = { cd e4 [2] e9 ea [2] c2 c6 [2] ec e4 [2] f8 ff [2] f7 e5 [2] e9 f8 [2] eb f9 [2] f0 ff [2] ec f8 [2] f0 d7 }

  condition:
    any of them
}