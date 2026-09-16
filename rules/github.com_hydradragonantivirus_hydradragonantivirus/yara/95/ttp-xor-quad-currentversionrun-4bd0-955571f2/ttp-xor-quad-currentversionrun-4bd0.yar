rule TTP_XOR_QUAD_CurrentVersionRun_4bd0 {
  strings:
    $key_4bd0 = { 18 bf [2] 3c b1 [2] 17 9d [2] 39 bf [2] 2d a4 [2] 22 be [2] 3c a3 [2] 3e a2 [2] 25 a4 [2] 39 a3 [2] 25 8c }

  condition:
    any of them
}