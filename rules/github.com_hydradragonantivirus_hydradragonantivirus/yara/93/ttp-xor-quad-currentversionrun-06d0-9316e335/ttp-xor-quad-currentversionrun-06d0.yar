rule TTP_XOR_QUAD_CurrentVersionRun_06d0 {
  strings:
    $key_06d0 = { 55 bf [2] 71 b1 [2] 5a 9d [2] 74 bf [2] 60 a4 [2] 6f be [2] 71 a3 [2] 73 a2 [2] 68 a4 [2] 74 a3 [2] 68 8c }

  condition:
    any of them
}