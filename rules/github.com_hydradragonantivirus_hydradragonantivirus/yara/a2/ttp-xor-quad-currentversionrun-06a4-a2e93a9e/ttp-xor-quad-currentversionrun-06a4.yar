rule TTP_XOR_QUAD_CurrentVersionRun_06a4 {
  strings:
    $key_06a4 = { 55 cb [2] 71 c5 [2] 5a e9 [2] 74 cb [2] 60 d0 [2] 6f ca [2] 71 d7 [2] 73 d6 [2] 68 d0 [2] 74 d7 [2] 68 f8 }

  condition:
    any of them
}