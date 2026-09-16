rule TTP_XOR_QUAD_CurrentVersionRun_6687 {
  strings:
    $key_6687 = { 35 e8 [2] 11 e6 [2] 3a ca [2] 14 e8 [2] 00 f3 [2] 0f e9 [2] 11 f4 [2] 13 f5 [2] 08 f3 [2] 14 f4 [2] 08 db }

  condition:
    any of them
}