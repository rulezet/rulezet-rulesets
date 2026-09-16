rule TTP_XOR_QUAD_CurrentVersionRun_66d0 {
  strings:
    $key_66d0 = { 35 bf [2] 11 b1 [2] 3a 9d [2] 14 bf [2] 00 a4 [2] 0f be [2] 11 a3 [2] 13 a2 [2] 08 a4 [2] 14 a3 [2] 08 8c }

  condition:
    any of them
}