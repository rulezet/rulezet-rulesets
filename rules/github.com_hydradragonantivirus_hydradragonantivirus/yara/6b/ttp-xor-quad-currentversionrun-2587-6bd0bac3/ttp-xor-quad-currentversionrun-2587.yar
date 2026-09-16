rule TTP_XOR_QUAD_CurrentVersionRun_2587 {
  strings:
    $key_2587 = { 76 e8 [2] 52 e6 [2] 79 ca [2] 57 e8 [2] 43 f3 [2] 4c e9 [2] 52 f4 [2] 50 f5 [2] 4b f3 [2] 57 f4 [2] 4b db }

  condition:
    any of them
}