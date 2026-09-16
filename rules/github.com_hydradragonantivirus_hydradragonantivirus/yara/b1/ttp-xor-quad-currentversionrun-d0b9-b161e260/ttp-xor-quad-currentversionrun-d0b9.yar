rule TTP_XOR_QUAD_CurrentVersionRun_d0b9 {
  strings:
    $key_d0b9 = { 83 d6 [2] a7 d8 [2] 8c f4 [2] a2 d6 [2] b6 cd [2] b9 d7 [2] a7 ca [2] a5 cb [2] be cd [2] a2 ca [2] be e5 }

  condition:
    any of them
}