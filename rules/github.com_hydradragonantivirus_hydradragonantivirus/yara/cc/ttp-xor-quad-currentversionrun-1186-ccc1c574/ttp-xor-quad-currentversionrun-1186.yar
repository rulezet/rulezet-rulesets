rule TTP_XOR_QUAD_CurrentVersionRun_1186 {
  strings:
    $key_1186 = { 42 e9 [2] 66 e7 [2] 4d cb [2] 63 e9 [2] 77 f2 [2] 78 e8 [2] 66 f5 [2] 64 f4 [2] 7f f2 [2] 63 f5 [2] 7f da }

  condition:
    any of them
}