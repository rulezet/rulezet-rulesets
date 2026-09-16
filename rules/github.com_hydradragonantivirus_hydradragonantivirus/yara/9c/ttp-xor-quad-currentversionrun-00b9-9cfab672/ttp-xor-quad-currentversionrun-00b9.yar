rule TTP_XOR_QUAD_CurrentVersionRun_00b9 {
  strings:
    $key_00b9 = { 53 d6 [2] 77 d8 [2] 5c f4 [2] 72 d6 [2] 66 cd [2] 69 d7 [2] 77 ca [2] 75 cb [2] 6e cd [2] 72 ca [2] 6e e5 }

  condition:
    any of them
}