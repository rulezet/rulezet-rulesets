rule TTP_XOR_QUAD_CurrentVersionRun_ddb9 {
  strings:
    $key_ddb9 = { 8e d6 [2] aa d8 [2] 81 f4 [2] af d6 [2] bb cd [2] b4 d7 [2] aa ca [2] a8 cb [2] b3 cd [2] af ca [2] b3 e5 }

  condition:
    any of them
}