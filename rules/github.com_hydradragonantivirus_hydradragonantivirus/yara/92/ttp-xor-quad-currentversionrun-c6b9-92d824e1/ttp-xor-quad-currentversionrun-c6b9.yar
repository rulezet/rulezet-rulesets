rule TTP_XOR_QUAD_CurrentVersionRun_c6b9 {
  strings:
    $key_c6b9 = { 95 d6 [2] b1 d8 [2] 9a f4 [2] b4 d6 [2] a0 cd [2] af d7 [2] b1 ca [2] b3 cb [2] a8 cd [2] b4 ca [2] a8 e5 }

  condition:
    any of them
}