rule TTP_XOR_QUAD_CurrentVersionRun_05b9 {
  strings:
    $key_05b9 = { 56 d6 [2] 72 d8 [2] 59 f4 [2] 77 d6 [2] 63 cd [2] 6c d7 [2] 72 ca [2] 70 cb [2] 6b cd [2] 77 ca [2] 6b e5 }

  condition:
    any of them
}