rule TTP_XOR_QUAD_CurrentVersionRun_97f2 {
  strings:
    $key_97f2 = { c4 9d [2] e0 93 [2] cb bf [2] e5 9d [2] f1 86 [2] fe 9c [2] e0 81 [2] e2 80 [2] f9 86 [2] e5 81 [2] f9 ae }

  condition:
    any of them
}