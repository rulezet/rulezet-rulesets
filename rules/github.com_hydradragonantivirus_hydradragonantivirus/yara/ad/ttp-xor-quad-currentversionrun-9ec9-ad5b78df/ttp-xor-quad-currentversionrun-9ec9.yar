rule TTP_XOR_QUAD_CurrentVersionRun_9ec9 {
  strings:
    $key_9ec9 = { cd a6 [2] e9 a8 [2] c2 84 [2] ec a6 [2] f8 bd [2] f7 a7 [2] e9 ba [2] eb bb [2] f0 bd [2] ec ba [2] f0 95 }

  condition:
    any of them
}