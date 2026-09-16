rule TTP_XOR_QUAD_CurrentVersionRun_859b {
  strings:
    $key_859b = { d6 f4 [2] f2 fa [2] d9 d6 [2] f7 f4 [2] e3 ef [2] ec f5 [2] f2 e8 [2] f0 e9 [2] eb ef [2] f7 e8 [2] eb c7 }

  condition:
    any of them
}