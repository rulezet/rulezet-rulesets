rule TTP_XOR_QUAD_CurrentVersionRun_c2b8 {
  strings:
    $key_c2b8 = { 91 d7 [2] b5 d9 [2] 9e f5 [2] b0 d7 [2] a4 cc [2] ab d6 [2] b5 cb [2] b7 ca [2] ac cc [2] b0 cb [2] ac e4 }

  condition:
    any of them
}