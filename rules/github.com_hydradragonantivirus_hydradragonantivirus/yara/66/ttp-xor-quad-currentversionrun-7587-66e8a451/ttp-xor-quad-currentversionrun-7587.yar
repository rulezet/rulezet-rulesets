rule TTP_XOR_QUAD_CurrentVersionRun_7587 {
  strings:
    $key_7587 = { 26 e8 [2] 02 e6 [2] 29 ca [2] 07 e8 [2] 13 f3 [2] 1c e9 [2] 02 f4 [2] 00 f5 [2] 1b f3 [2] 07 f4 [2] 1b db }

  condition:
    any of them
}