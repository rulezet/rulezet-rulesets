rule TTP_XOR_QUAD_CurrentVersionRun_9b90 {
  strings:
    $key_9b90 = { c8 ff [2] ec f1 [2] c7 dd [2] e9 ff [2] fd e4 [2] f2 fe [2] ec e3 [2] ee e2 [2] f5 e4 [2] e9 e3 [2] f5 cc }

  condition:
    any of them
}