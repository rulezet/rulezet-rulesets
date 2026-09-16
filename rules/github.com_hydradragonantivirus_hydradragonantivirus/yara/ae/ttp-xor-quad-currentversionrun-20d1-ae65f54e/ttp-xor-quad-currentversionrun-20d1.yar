rule TTP_XOR_QUAD_CurrentVersionRun_20d1 {
  strings:
    $key_20d1 = { 73 be [2] 57 b0 [2] 7c 9c [2] 52 be [2] 46 a5 [2] 49 bf [2] 57 a2 [2] 55 a3 [2] 4e a5 [2] 52 a2 [2] 4e 8d }

  condition:
    any of them
}