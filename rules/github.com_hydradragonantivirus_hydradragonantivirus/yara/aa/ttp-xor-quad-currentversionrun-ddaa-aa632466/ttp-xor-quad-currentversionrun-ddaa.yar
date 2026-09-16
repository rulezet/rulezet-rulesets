rule TTP_XOR_QUAD_CurrentVersionRun_ddaa {
  strings:
    $key_ddaa = { 8e c5 [2] aa cb [2] 81 e7 [2] af c5 [2] bb de [2] b4 c4 [2] aa d9 [2] a8 d8 [2] b3 de [2] af d9 [2] b3 f6 }

  condition:
    any of them
}