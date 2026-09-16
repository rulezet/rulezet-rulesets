rule TTP_XOR_QUAD_CurrentVersionRun_4ed1 {
  strings:
    $key_4ed1 = { 1d be [2] 39 b0 [2] 12 9c [2] 3c be [2] 28 a5 [2] 27 bf [2] 39 a2 [2] 3b a3 [2] 20 a5 [2] 3c a2 [2] 20 8d }

  condition:
    any of them
}