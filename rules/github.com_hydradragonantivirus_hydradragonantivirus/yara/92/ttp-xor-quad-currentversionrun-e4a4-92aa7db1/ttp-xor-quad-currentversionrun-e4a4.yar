rule TTP_XOR_QUAD_CurrentVersionRun_e4a4 {
  strings:
    $key_e4a4 = { b7 cb [2] 93 c5 [2] b8 e9 [2] 96 cb [2] 82 d0 [2] 8d ca [2] 93 d7 [2] 91 d6 [2] 8a d0 [2] 96 d7 [2] 8a f8 }

  condition:
    any of them
}