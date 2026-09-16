rule TTP_XOR_QUAD_CurrentVersionRun_dca4 {
  strings:
    $key_dca4 = { 8f cb [2] ab c5 [2] 80 e9 [2] ae cb [2] ba d0 [2] b5 ca [2] ab d7 [2] a9 d6 [2] b2 d0 [2] ae d7 [2] b2 f8 }

  condition:
    any of them
}