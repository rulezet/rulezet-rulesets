rule TTP_XOR_QUAD_CurrentVersionRun_53d0 {
  strings:
    $key_53d0 = { 00 bf [2] 24 b1 [2] 0f 9d [2] 21 bf [2] 35 a4 [2] 3a be [2] 24 a3 [2] 26 a2 [2] 3d a4 [2] 21 a3 [2] 3d 8c }

  condition:
    any of them
}