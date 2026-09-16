rule TTP_XOR_QUAD_CurrentVersionRun_86be {
  strings:
    $key_86be = { d5 d1 [2] f1 df [2] da f3 [2] f4 d1 [2] e0 ca [2] ef d0 [2] f1 cd [2] f3 cc [2] e8 ca [2] f4 cd [2] e8 e2 }

  condition:
    any of them
}