rule TTP_XOR_QUAD_CurrentVersionRun_31d1 {
  strings:
    $key_31d1 = { 62 be [2] 46 b0 [2] 6d 9c [2] 43 be [2] 57 a5 [2] 58 bf [2] 46 a2 [2] 44 a3 [2] 5f a5 [2] 43 a2 [2] 5f 8d }

  condition:
    any of them
}