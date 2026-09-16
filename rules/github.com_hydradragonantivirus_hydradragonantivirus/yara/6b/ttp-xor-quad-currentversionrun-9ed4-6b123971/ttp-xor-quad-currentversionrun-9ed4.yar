rule TTP_XOR_QUAD_CurrentVersionRun_9ed4 {
  strings:
    $key_9ed4 = { cd bb [2] e9 b5 [2] c2 99 [2] ec bb [2] f8 a0 [2] f7 ba [2] e9 a7 [2] eb a6 [2] f0 a0 [2] ec a7 [2] f0 88 }

  condition:
    any of them
}