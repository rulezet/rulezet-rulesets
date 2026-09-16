rule TTP_XOR_QUAD_CurrentVersionRun_1c96 {
  strings:
    $key_1c96 = { 4f f9 [2] 6b f7 [2] 40 db [2] 6e f9 [2] 7a e2 [2] 75 f8 [2] 6b e5 [2] 69 e4 [2] 72 e2 [2] 6e e5 [2] 72 ca }

  condition:
    any of them
}