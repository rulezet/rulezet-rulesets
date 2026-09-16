rule TTP_XOR_QUAD_CurrentVersionRun_6286 {
  strings:
    $key_6286 = { 31 e9 [2] 15 e7 [2] 3e cb [2] 10 e9 [2] 04 f2 [2] 0b e8 [2] 15 f5 [2] 17 f4 [2] 0c f2 [2] 10 f5 [2] 0c da }

  condition:
    any of them
}