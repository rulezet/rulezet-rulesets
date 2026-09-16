rule TTP_XOR_QUAD_CurrentVersionRun_c2b9 {
  strings:
    $key_c2b9 = { 91 d6 [2] b5 d8 [2] 9e f4 [2] b0 d6 [2] a4 cd [2] ab d7 [2] b5 ca [2] b7 cb [2] ac cd [2] b0 ca [2] ac e5 }

  condition:
    any of them
}