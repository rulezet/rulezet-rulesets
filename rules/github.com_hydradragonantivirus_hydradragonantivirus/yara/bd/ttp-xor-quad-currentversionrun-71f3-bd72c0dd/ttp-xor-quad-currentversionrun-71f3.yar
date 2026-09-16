rule TTP_XOR_QUAD_CurrentVersionRun_71f3 {
  strings:
    $key_71f3 = { 22 9c [2] 06 92 [2] 2d be [2] 03 9c [2] 17 87 [2] 18 9d [2] 06 80 [2] 04 81 [2] 1f 87 [2] 03 80 [2] 1f af }

  condition:
    any of them
}