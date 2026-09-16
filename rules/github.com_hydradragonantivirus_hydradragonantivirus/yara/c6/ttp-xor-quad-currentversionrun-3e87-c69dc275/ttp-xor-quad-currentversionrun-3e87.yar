rule TTP_XOR_QUAD_CurrentVersionRun_3e87 {
  strings:
    $key_3e87 = { 6d e8 [2] 49 e6 [2] 62 ca [2] 4c e8 [2] 58 f3 [2] 57 e9 [2] 49 f4 [2] 4b f5 [2] 50 f3 [2] 4c f4 [2] 50 db }

  condition:
    any of them
}