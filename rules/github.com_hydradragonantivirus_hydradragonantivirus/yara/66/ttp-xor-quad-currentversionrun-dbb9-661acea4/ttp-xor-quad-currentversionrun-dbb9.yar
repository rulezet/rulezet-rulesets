rule TTP_XOR_QUAD_CurrentVersionRun_dbb9 {
  strings:
    $key_dbb9 = { 88 d6 [2] ac d8 [2] 87 f4 [2] a9 d6 [2] bd cd [2] b2 d7 [2] ac ca [2] ae cb [2] b5 cd [2] a9 ca [2] b5 e5 }

  condition:
    any of them
}