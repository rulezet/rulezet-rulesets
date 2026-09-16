rule TTP_XOR_QUAD_CurrentVersionRun_99b3 {
  strings:
    $key_99b3 = { ca dc [2] ee d2 [2] c5 fe [2] eb dc [2] ff c7 [2] f0 dd [2] ee c0 [2] ec c1 [2] f7 c7 [2] eb c0 [2] f7 ef }

  condition:
    any of them
}