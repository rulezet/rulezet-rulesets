rule TTP_XOR_QUAD_CurrentVersionRun_ebd0 {
  strings:
    $key_ebd0 = { b8 bf [2] 9c b1 [2] b7 9d [2] 99 bf [2] 8d a4 [2] 82 be [2] 9c a3 [2] 9e a2 [2] 85 a4 [2] 99 a3 [2] 85 8c }

  condition:
    any of them
}