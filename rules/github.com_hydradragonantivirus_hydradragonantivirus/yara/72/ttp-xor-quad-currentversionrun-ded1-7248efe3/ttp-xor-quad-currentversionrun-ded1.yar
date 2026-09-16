rule TTP_XOR_QUAD_CurrentVersionRun_ded1 {
  strings:
    $key_ded1 = { 8d be [2] a9 b0 [2] 82 9c [2] ac be [2] b8 a5 [2] b7 bf [2] a9 a2 [2] ab a3 [2] b0 a5 [2] ac a2 [2] b0 8d }

  condition:
    any of them
}