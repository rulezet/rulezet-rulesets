rule TTP_XOR_QUAD_CurrentVersionRun_0687 {
  strings:
    $key_0687 = { 55 e8 [2] 71 e6 [2] 5a ca [2] 74 e8 [2] 60 f3 [2] 6f e9 [2] 71 f4 [2] 73 f5 [2] 68 f3 [2] 74 f4 [2] 68 db }

  condition:
    any of them
}