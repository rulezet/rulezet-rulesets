rule TTP_XOR_QUAD_CurrentVersionRun_72a4 {
  strings:
    $key_72a4 = { 21 cb [2] 05 c5 [2] 2e e9 [2] 00 cb [2] 14 d0 [2] 1b ca [2] 05 d7 [2] 07 d6 [2] 1c d0 [2] 00 d7 [2] 1c f8 }

  condition:
    any of them
}