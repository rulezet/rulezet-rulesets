rule TTP_XOR_QUAD_CurrentVersionRun_6d87 {
  strings:
    $key_6d87 = { 3e e8 [2] 1a e6 [2] 31 ca [2] 1f e8 [2] 0b f3 [2] 04 e9 [2] 1a f4 [2] 18 f5 [2] 03 f3 [2] 1f f4 [2] 03 db }

  condition:
    any of them
}