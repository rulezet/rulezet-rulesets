rule TTP_XOR_QUAD_CurrentVersionRun_0e87 {
  strings:
    $key_0e87 = { 5d e8 [2] 79 e6 [2] 52 ca [2] 7c e8 [2] 68 f3 [2] 67 e9 [2] 79 f4 [2] 7b f5 [2] 60 f3 [2] 7c f4 [2] 60 db }

  condition:
    any of them
}