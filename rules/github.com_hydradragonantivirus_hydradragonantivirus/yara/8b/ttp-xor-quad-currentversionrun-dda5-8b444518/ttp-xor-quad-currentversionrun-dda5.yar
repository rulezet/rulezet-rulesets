rule TTP_XOR_QUAD_CurrentVersionRun_dda5 {
  strings:
    $key_dda5 = { 8e ca [2] aa c4 [2] 81 e8 [2] af ca [2] bb d1 [2] b4 cb [2] aa d6 [2] a8 d7 [2] b3 d1 [2] af d6 [2] b3 f9 }

  condition:
    any of them
}