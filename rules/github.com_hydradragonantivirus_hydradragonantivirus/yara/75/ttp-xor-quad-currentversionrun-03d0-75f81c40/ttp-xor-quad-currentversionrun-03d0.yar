rule TTP_XOR_QUAD_CurrentVersionRun_03d0 {
  strings:
    $key_03d0 = { 50 bf [2] 74 b1 [2] 5f 9d [2] 71 bf [2] 65 a4 [2] 6a be [2] 74 a3 [2] 76 a2 [2] 6d a4 [2] 71 a3 [2] 6d 8c }

  condition:
    any of them
}