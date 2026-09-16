rule TTP_XOR_QUAD_CurrentVersionRun_08d1 {
  strings:
    $key_08d1 = { 5b be [2] 7f b0 [2] 54 9c [2] 7a be [2] 6e a5 [2] 61 bf [2] 7f a2 [2] 7d a3 [2] 66 a5 [2] 7a a2 [2] 66 8d }

  condition:
    any of them
}