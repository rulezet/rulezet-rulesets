rule TTP_XOR_QUAD_CurrentVersionRun_2987 {
  strings:
    $key_2987 = { 7a e8 [2] 5e e6 [2] 75 ca [2] 5b e8 [2] 4f f3 [2] 40 e9 [2] 5e f4 [2] 5c f5 [2] 47 f3 [2] 5b f4 [2] 47 db }

  condition:
    any of them
}