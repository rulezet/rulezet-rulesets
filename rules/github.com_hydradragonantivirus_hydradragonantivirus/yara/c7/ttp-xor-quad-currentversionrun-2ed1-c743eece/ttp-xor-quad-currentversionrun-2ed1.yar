rule TTP_XOR_QUAD_CurrentVersionRun_2ed1 {
  strings:
    $key_2ed1 = { 7d be [2] 59 b0 [2] 72 9c [2] 5c be [2] 48 a5 [2] 47 bf [2] 59 a2 [2] 5b a3 [2] 40 a5 [2] 5c a2 [2] 40 8d }

  condition:
    any of them
}