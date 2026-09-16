rule TTP_XOR_QUAD_CurrentVersionRun_7d87 {
  strings:
    $key_7d87 = { 2e e8 [2] 0a e6 [2] 21 ca [2] 0f e8 [2] 1b f3 [2] 14 e9 [2] 0a f4 [2] 08 f5 [2] 13 f3 [2] 0f f4 [2] 13 db }

  condition:
    any of them
}