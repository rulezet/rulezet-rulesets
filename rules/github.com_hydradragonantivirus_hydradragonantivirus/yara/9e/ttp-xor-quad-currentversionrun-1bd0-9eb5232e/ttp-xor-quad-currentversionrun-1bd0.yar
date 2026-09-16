rule TTP_XOR_QUAD_CurrentVersionRun_1bd0 {
  strings:
    $key_1bd0 = { 48 bf [2] 6c b1 [2] 47 9d [2] 69 bf [2] 7d a4 [2] 72 be [2] 6c a3 [2] 6e a2 [2] 75 a4 [2] 69 a3 [2] 75 8c }

  condition:
    any of them
}