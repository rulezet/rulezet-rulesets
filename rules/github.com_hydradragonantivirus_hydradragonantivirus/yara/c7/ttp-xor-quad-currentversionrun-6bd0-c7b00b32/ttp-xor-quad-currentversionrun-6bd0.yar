rule TTP_XOR_QUAD_CurrentVersionRun_6bd0 {
  strings:
    $key_6bd0 = { 38 bf [2] 1c b1 [2] 37 9d [2] 19 bf [2] 0d a4 [2] 02 be [2] 1c a3 [2] 1e a2 [2] 05 a4 [2] 19 a3 [2] 05 8c }

  condition:
    any of them
}