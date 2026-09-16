rule TTP_XOR_QUAD_CurrentVersionRun_96b9 {
  strings:
    $key_96b9 = { c5 d6 [2] e1 d8 [2] ca f4 [2] e4 d6 [2] f0 cd [2] ff d7 [2] e1 ca [2] e3 cb [2] f8 cd [2] e4 ca [2] f8 e5 }

  condition:
    any of them
}