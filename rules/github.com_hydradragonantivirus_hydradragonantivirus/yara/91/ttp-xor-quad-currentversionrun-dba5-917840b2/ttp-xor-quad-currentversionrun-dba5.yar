rule TTP_XOR_QUAD_CurrentVersionRun_dba5 {
  strings:
    $key_dba5 = { 88 ca [2] ac c4 [2] 87 e8 [2] a9 ca [2] bd d1 [2] b2 cb [2] ac d6 [2] ae d7 [2] b5 d1 [2] a9 d6 [2] b5 f9 }

  condition:
    any of them
}