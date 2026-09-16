rule TTP_XOR_QUAD_CurrentVersionRun_97bf {
  strings:
    $key_97bf = { c4 d0 [2] e0 de [2] cb f2 [2] e5 d0 [2] f1 cb [2] fe d1 [2] e0 cc [2] e2 cd [2] f9 cb [2] e5 cc [2] f9 e3 }

  condition:
    any of them
}