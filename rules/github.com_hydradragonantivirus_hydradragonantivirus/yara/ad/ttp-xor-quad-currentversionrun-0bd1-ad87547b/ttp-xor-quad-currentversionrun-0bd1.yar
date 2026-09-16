rule TTP_XOR_QUAD_CurrentVersionRun_0bd1 {
  strings:
    $key_0bd1 = { 58 be [2] 7c b0 [2] 57 9c [2] 79 be [2] 6d a5 [2] 62 bf [2] 7c a2 [2] 7e a3 [2] 65 a5 [2] 79 a2 [2] 65 8d }

  condition:
    any of them
}