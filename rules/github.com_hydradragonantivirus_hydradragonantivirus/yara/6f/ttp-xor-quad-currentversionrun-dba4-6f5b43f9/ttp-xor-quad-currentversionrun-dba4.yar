rule TTP_XOR_QUAD_CurrentVersionRun_dba4 {
  strings:
    $key_dba4 = { 88 cb [2] ac c5 [2] 87 e9 [2] a9 cb [2] bd d0 [2] b2 ca [2] ac d7 [2] ae d6 [2] b5 d0 [2] a9 d7 [2] b5 f8 }

  condition:
    any of them
}