rule TTP_XOR_QUAD_CurrentVersionRun_37a5 {
  strings:
    $key_37a5 = { 64 ca [2] 40 c4 [2] 6b e8 [2] 45 ca [2] 51 d1 [2] 5e cb [2] 40 d6 [2] 42 d7 [2] 59 d1 [2] 45 d6 [2] 59 f9 }

  condition:
    any of them
}