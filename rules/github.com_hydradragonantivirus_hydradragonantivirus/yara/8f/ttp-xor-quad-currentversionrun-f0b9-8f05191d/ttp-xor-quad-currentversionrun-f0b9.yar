rule TTP_XOR_QUAD_CurrentVersionRun_f0b9 {
  strings:
    $key_f0b9 = { a3 d6 [2] 87 d8 [2] ac f4 [2] 82 d6 [2] 96 cd [2] 99 d7 [2] 87 ca [2] 85 cb [2] 9e cd [2] 82 ca [2] 9e e5 }

  condition:
    any of them
}