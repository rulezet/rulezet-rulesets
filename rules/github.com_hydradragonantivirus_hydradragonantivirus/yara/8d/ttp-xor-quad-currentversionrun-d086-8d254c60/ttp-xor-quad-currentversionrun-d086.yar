rule TTP_XOR_QUAD_CurrentVersionRun_d086 {
  strings:
    $key_d086 = { 83 e9 [2] a7 e7 [2] 8c cb [2] a2 e9 [2] b6 f2 [2] b9 e8 [2] a7 f5 [2] a5 f4 [2] be f2 [2] a2 f5 [2] be da }

  condition:
    any of them
}