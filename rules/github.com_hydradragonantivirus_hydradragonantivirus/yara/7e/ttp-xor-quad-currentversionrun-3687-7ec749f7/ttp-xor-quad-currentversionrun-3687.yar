rule TTP_XOR_QUAD_CurrentVersionRun_3687 {
  strings:
    $key_3687 = { 65 e8 [2] 41 e6 [2] 6a ca [2] 44 e8 [2] 50 f3 [2] 5f e9 [2] 41 f4 [2] 43 f5 [2] 58 f3 [2] 44 f4 [2] 58 db }

  condition:
    any of them
}