rule TTP_XOR_QUAD_CurrentVersionRun_eda4 {
  strings:
    $key_eda4 = { be cb [2] 9a c5 [2] b1 e9 [2] 9f cb [2] 8b d0 [2] 84 ca [2] 9a d7 [2] 98 d6 [2] 83 d0 [2] 9f d7 [2] 83 f8 }

  condition:
    any of them
}