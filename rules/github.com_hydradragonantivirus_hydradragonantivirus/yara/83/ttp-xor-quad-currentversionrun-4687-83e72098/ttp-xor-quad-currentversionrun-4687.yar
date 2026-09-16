rule TTP_XOR_QUAD_CurrentVersionRun_4687 {
  strings:
    $key_4687 = { 15 e8 [2] 31 e6 [2] 1a ca [2] 34 e8 [2] 20 f3 [2] 2f e9 [2] 31 f4 [2] 33 f5 [2] 28 f3 [2] 34 f4 [2] 28 db }

  condition:
    any of them
}