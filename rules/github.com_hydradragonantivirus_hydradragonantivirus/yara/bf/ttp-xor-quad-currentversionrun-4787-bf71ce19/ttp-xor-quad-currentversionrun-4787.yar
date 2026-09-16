rule TTP_XOR_QUAD_CurrentVersionRun_4787 {
  strings:
    $key_4787 = { 14 e8 [2] 30 e6 [2] 1b ca [2] 35 e8 [2] 21 f3 [2] 2e e9 [2] 30 f4 [2] 32 f5 [2] 29 f3 [2] 35 f4 [2] 29 db }

  condition:
    any of them
}