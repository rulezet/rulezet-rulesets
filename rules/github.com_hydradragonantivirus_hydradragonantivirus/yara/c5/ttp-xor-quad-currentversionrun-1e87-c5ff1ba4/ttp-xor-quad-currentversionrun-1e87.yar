rule TTP_XOR_QUAD_CurrentVersionRun_1e87 {
  strings:
    $key_1e87 = { 4d e8 [2] 69 e6 [2] 42 ca [2] 6c e8 [2] 78 f3 [2] 77 e9 [2] 69 f4 [2] 6b f5 [2] 70 f3 [2] 6c f4 [2] 70 db }

  condition:
    any of them
}