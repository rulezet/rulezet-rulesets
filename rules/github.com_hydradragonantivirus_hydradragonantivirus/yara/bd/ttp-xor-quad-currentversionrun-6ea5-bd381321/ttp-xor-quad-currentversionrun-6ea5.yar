rule TTP_XOR_QUAD_CurrentVersionRun_6ea5 {
  strings:
    $key_6ea5 = { 3d ca [2] 19 c4 [2] 32 e8 [2] 1c ca [2] 08 d1 [2] 07 cb [2] 19 d6 [2] 1b d7 [2] 00 d1 [2] 1c d6 [2] 00 f9 }

  condition:
    any of them
}