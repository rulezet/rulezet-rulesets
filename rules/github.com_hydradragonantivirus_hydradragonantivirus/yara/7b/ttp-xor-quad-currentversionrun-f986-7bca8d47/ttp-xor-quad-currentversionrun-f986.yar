rule TTP_XOR_QUAD_CurrentVersionRun_f986 {
  strings:
    $key_f986 = { aa e9 [2] 8e e7 [2] a5 cb [2] 8b e9 [2] 9f f2 [2] 90 e8 [2] 8e f5 [2] 8c f4 [2] 97 f2 [2] 8b f5 [2] 97 da }

  condition:
    any of them
}