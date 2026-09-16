rule TTP_XOR_QUAD_CurrentVersionRun_c4b9 {
  strings:
    $key_c4b9 = { 97 d6 [2] b3 d8 [2] 98 f4 [2] b6 d6 [2] a2 cd [2] ad d7 [2] b3 ca [2] b1 cb [2] aa cd [2] b6 ca [2] aa e5 }

  condition:
    any of them
}