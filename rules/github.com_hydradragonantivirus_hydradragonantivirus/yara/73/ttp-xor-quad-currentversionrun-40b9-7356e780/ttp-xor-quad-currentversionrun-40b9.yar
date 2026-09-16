rule TTP_XOR_QUAD_CurrentVersionRun_40b9 {
  strings:
    $key_40b9 = { 13 d6 [2] 37 d8 [2] 1c f4 [2] 32 d6 [2] 26 cd [2] 29 d7 [2] 37 ca [2] 35 cb [2] 2e cd [2] 32 ca [2] 2e e5 }

  condition:
    any of them
}