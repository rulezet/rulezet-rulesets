rule TTP_XOR_QUAD_CurrentVersionRun_36d0 {
  strings:
    $key_36d0 = { 65 bf [2] 41 b1 [2] 6a 9d [2] 44 bf [2] 50 a4 [2] 5f be [2] 41 a3 [2] 43 a2 [2] 58 a4 [2] 44 a3 [2] 58 8c }

  condition:
    any of them
}