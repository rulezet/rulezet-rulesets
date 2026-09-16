rule TTP_XOR_QUAD_CurrentVersionRun_0986 {
  strings:
    $key_0986 = { 5a e9 [2] 7e e7 [2] 55 cb [2] 7b e9 [2] 6f f2 [2] 60 e8 [2] 7e f5 [2] 7c f4 [2] 67 f2 [2] 7b f5 [2] 67 da }

  condition:
    any of them
}