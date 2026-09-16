rule TTP_XOR_QUAD_CurrentVersionRun_deb9 {
  strings:
    $key_deb9 = { 8d d6 [2] a9 d8 [2] 82 f4 [2] ac d6 [2] b8 cd [2] b7 d7 [2] a9 ca [2] ab cb [2] b0 cd [2] ac ca [2] b0 e5 }

  condition:
    any of them
}