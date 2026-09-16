rule TTP_XOR_QUAD_CurrentVersionRun_dca5 {
  strings:
    $key_dca5 = { 8f ca [2] ab c4 [2] 80 e8 [2] ae ca [2] ba d1 [2] b5 cb [2] ab d6 [2] a9 d7 [2] b2 d1 [2] ae d6 [2] b2 f9 }

  condition:
    any of them
}