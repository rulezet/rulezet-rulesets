rule TTP_XOR_QUAD_CurrentVersionRun_7e87 {
  strings:
    $key_7e87 = { 2d e8 [2] 09 e6 [2] 22 ca [2] 0c e8 [2] 18 f3 [2] 17 e9 [2] 09 f4 [2] 0b f5 [2] 10 f3 [2] 0c f4 [2] 10 db }

  condition:
    any of them
}