rule TTP_XOR_QUAD_CurrentVersionRun_2e87 {
  strings:
    $key_2e87 = { 7d e8 [2] 59 e6 [2] 72 ca [2] 5c e8 [2] 48 f3 [2] 47 e9 [2] 59 f4 [2] 5b f5 [2] 40 f3 [2] 5c f4 [2] 40 db }

  condition:
    any of them
}