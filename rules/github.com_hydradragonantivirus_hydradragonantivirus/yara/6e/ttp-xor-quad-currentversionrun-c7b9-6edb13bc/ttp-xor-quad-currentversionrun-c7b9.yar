rule TTP_XOR_QUAD_CurrentVersionRun_c7b9 {
  strings:
    $key_c7b9 = { 94 d6 [2] b0 d8 [2] 9b f4 [2] b5 d6 [2] a1 cd [2] ae d7 [2] b0 ca [2] b2 cb [2] a9 cd [2] b5 ca [2] a9 e5 }

  condition:
    any of them
}