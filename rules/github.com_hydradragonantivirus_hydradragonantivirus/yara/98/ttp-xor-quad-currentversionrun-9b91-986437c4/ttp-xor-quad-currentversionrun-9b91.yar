rule TTP_XOR_QUAD_CurrentVersionRun_9b91 {
  strings:
    $key_9b91 = { c8 fe [2] ec f0 [2] c7 dc [2] e9 fe [2] fd e5 [2] f2 ff [2] ec e2 [2] ee e3 [2] f5 e5 [2] e9 e2 [2] f5 cd }

  condition:
    any of them
}