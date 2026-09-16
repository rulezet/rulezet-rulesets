rule TTP_XOR_QUAD_CurrentVersionRun_7ad0 {
  strings:
    $key_7ad0 = { 29 bf [2] 0d b1 [2] 26 9d [2] 08 bf [2] 1c a4 [2] 13 be [2] 0d a3 [2] 0f a2 [2] 14 a4 [2] 08 a3 [2] 14 8c }

  condition:
    any of them
}