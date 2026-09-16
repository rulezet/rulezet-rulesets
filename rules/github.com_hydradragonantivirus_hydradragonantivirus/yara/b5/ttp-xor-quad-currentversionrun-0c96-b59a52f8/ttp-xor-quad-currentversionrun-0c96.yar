rule TTP_XOR_QUAD_CurrentVersionRun_0c96 {
  strings:
    $key_0c96 = { 5f f9 [2] 7b f7 [2] 50 db [2] 7e f9 [2] 6a e2 [2] 65 f8 [2] 7b e5 [2] 79 e4 [2] 62 e2 [2] 7e e5 [2] 62 ca }

  condition:
    any of them
}