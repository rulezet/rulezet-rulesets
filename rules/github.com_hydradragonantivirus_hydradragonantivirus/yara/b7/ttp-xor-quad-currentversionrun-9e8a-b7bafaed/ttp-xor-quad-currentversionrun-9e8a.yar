rule TTP_XOR_QUAD_CurrentVersionRun_9e8a {
  strings:
    $key_9e8a = { cd e5 [2] e9 eb [2] c2 c7 [2] ec e5 [2] f8 fe [2] f7 e4 [2] e9 f9 [2] eb f8 [2] f0 fe [2] ec f9 [2] f0 d6 }

  condition:
    any of them
}