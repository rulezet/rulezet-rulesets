rule TTP_XOR_QUAD_CurrentVersionRun_859d {
  strings:
    $key_859d = { d6 f2 [2] f2 fc [2] d9 d0 [2] f7 f2 [2] e3 e9 [2] ec f3 [2] f2 ee [2] f0 ef [2] eb e9 [2] f7 ee [2] eb c1 }

  condition:
    any of them
}