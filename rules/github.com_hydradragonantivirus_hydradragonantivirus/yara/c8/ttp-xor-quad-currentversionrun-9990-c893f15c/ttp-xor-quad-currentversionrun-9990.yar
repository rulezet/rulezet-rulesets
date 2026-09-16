rule TTP_XOR_QUAD_CurrentVersionRun_9990 {
  strings:
    $key_9990 = { ca ff [2] ee f1 [2] c5 dd [2] eb ff [2] ff e4 [2] f0 fe [2] ee e3 [2] ec e2 [2] f7 e4 [2] eb e3 [2] f7 cc }

  condition:
    any of them
}