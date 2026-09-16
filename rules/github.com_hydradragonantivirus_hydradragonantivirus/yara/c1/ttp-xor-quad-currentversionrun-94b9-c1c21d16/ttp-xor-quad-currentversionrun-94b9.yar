rule TTP_XOR_QUAD_CurrentVersionRun_94b9 {
  strings:
    $key_94b9 = { c7 d6 [2] e3 d8 [2] c8 f4 [2] e6 d6 [2] f2 cd [2] fd d7 [2] e3 ca [2] e1 cb [2] fa cd [2] e6 ca [2] fa e5 }

  condition:
    any of them
}