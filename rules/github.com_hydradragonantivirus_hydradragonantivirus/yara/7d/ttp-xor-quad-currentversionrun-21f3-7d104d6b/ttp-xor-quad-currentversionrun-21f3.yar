rule TTP_XOR_QUAD_CurrentVersionRun_21f3 {
  strings:
    $key_21f3 = { 72 9c [2] 56 92 [2] 7d be [2] 53 9c [2] 47 87 [2] 48 9d [2] 56 80 [2] 54 81 [2] 4f 87 [2] 53 80 [2] 4f af }

  condition:
    any of them
}