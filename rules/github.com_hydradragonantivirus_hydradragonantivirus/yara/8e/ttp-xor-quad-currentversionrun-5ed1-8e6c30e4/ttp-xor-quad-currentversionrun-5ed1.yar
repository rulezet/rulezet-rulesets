rule TTP_XOR_QUAD_CurrentVersionRun_5ed1 {
  strings:
    $key_5ed1 = { 0d be [2] 29 b0 [2] 02 9c [2] 2c be [2] 38 a5 [2] 37 bf [2] 29 a2 [2] 2b a3 [2] 30 a5 [2] 2c a2 [2] 30 8d }

  condition:
    any of them
}