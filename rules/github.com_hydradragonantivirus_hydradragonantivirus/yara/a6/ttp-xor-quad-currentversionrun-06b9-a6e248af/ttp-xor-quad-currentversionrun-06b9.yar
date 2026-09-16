rule TTP_XOR_QUAD_CurrentVersionRun_06b9 {
  strings:
    $key_06b9 = { 55 d6 [2] 71 d8 [2] 5a f4 [2] 74 d6 [2] 60 cd [2] 6f d7 [2] 71 ca [2] 73 cb [2] 68 cd [2] 74 ca [2] 68 e5 }

  condition:
    any of them
}