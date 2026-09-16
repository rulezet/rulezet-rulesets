rule TTP_XOR_QUAD_CurrentVersionRun_1687 {
  strings:
    $key_1687 = { 45 e8 [2] 61 e6 [2] 4a ca [2] 64 e8 [2] 70 f3 [2] 7f e9 [2] 61 f4 [2] 63 f5 [2] 78 f3 [2] 64 f4 [2] 78 db }

  condition:
    any of them
}