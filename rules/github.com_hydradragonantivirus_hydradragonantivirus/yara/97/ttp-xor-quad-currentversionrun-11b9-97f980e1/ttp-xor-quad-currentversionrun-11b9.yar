rule TTP_XOR_QUAD_CurrentVersionRun_11b9 {
  strings:
    $key_11b9 = { 42 d6 [2] 66 d8 [2] 4d f4 [2] 63 d6 [2] 77 cd [2] 78 d7 [2] 66 ca [2] 64 cb [2] 7f cd [2] 63 ca [2] 7f e5 }

  condition:
    any of them
}