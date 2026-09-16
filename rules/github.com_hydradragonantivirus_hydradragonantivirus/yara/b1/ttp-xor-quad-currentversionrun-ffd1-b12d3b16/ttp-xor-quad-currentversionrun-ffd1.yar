rule TTP_XOR_QUAD_CurrentVersionRun_ffd1 {
  strings:
    $key_ffd1 = { ac be [2] 88 b0 [2] a3 9c [2] 8d be [2] 99 a5 [2] 96 bf [2] 88 a2 [2] 8a a3 [2] 91 a5 [2] 8d a2 [2] 91 8d }

  condition:
    any of them
}