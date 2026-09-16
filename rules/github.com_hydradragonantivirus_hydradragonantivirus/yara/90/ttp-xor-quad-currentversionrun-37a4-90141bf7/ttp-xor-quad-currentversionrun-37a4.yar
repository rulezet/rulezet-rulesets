rule TTP_XOR_QUAD_CurrentVersionRun_37a4 {
  strings:
    $key_37a4 = { 64 cb [2] 40 c5 [2] 6b e9 [2] 45 cb [2] 51 d0 [2] 5e ca [2] 40 d7 [2] 42 d6 [2] 59 d0 [2] 45 d7 [2] 59 f8 }

  condition:
    any of them
}