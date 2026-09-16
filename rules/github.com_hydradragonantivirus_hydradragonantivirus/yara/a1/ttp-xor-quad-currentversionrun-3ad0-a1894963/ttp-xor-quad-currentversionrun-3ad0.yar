rule TTP_XOR_QUAD_CurrentVersionRun_3ad0 {
  strings:
    $key_3ad0 = { 69 bf [2] 4d b1 [2] 66 9d [2] 48 bf [2] 5c a4 [2] 53 be [2] 4d a3 [2] 4f a2 [2] 54 a4 [2] 48 a3 [2] 54 8c }

  condition:
    any of them
}