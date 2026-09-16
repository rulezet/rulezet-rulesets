rule TTP_XOR_QUAD_CurrentVersionRun_43d0 {
  strings:
    $key_43d0 = { 10 bf [2] 34 b1 [2] 1f 9d [2] 31 bf [2] 25 a4 [2] 2a be [2] 34 a3 [2] 36 a2 [2] 2d a4 [2] 31 a3 [2] 2d 8c }

  condition:
    any of them
}