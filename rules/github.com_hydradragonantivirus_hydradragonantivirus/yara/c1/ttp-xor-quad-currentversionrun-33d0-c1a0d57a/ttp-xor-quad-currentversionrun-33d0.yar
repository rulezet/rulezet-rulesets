rule TTP_XOR_QUAD_CurrentVersionRun_33d0 {
  strings:
    $key_33d0 = { 60 bf [2] 44 b1 [2] 6f 9d [2] 41 bf [2] 55 a4 [2] 5a be [2] 44 a3 [2] 46 a2 [2] 5d a4 [2] 41 a3 [2] 5d 8c }

  condition:
    any of them
}