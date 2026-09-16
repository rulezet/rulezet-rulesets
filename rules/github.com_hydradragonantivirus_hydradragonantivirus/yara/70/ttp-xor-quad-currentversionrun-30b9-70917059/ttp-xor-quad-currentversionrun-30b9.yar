rule TTP_XOR_QUAD_CurrentVersionRun_30b9 {
  strings:
    $key_30b9 = { 63 d6 [2] 47 d8 [2] 6c f4 [2] 42 d6 [2] 56 cd [2] 59 d7 [2] 47 ca [2] 45 cb [2] 5e cd [2] 42 ca [2] 5e e5 }

  condition:
    any of them
}