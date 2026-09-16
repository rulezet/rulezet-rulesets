rule TTP_XOR_QUAD_CurrentVersionRun_dda4 {
  strings:
    $key_dda4 = { 8e cb [2] aa c5 [2] 81 e9 [2] af cb [2] bb d0 [2] b4 ca [2] aa d7 [2] a8 d6 [2] b3 d0 [2] af d7 [2] b3 f8 }

  condition:
    any of them
}