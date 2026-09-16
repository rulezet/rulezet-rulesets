rule TTP_XOR_QUAD_CurrentVersionRun_23d0 {
  strings:
    $key_23d0 = { 70 bf [2] 54 b1 [2] 7f 9d [2] 51 bf [2] 45 a4 [2] 4a be [2] 54 a3 [2] 56 a2 [2] 4d a4 [2] 51 a3 [2] 4d 8c }

  condition:
    any of them
}