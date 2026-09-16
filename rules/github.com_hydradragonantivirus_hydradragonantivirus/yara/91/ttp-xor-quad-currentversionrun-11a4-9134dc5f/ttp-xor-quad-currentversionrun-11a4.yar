rule TTP_XOR_QUAD_CurrentVersionRun_11a4 {
  strings:
    $key_11a4 = { 42 cb [2] 66 c5 [2] 4d e9 [2] 63 cb [2] 77 d0 [2] 78 ca [2] 66 d7 [2] 64 d6 [2] 7f d0 [2] 63 d7 [2] 7f f8 }

  condition:
    any of them
}