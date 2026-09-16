rule TTP_XOR_QUAD_CurrentVersionRun_93bf {
  strings:
    $key_93bf = { c0 d0 [2] e4 de [2] cf f2 [2] e1 d0 [2] f5 cb [2] fa d1 [2] e4 cc [2] e6 cd [2] fd cb [2] e1 cc [2] fd e3 }

  condition:
    any of them
}