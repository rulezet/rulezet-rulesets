rule TTP_XOR_QUAD_CurrentVersionRun_77b9 {
  strings:
    $key_77b9 = { 24 d6 [2] 00 d8 [2] 2b f4 [2] 05 d6 [2] 11 cd [2] 1e d7 [2] 00 ca [2] 02 cb [2] 19 cd [2] 05 ca [2] 19 e5 }

  condition:
    any of them
}