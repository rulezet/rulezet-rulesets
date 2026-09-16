rule TTP_XOR_QUAD_CurrentVersionRun_76d0 {
  strings:
    $key_76d0 = { 25 bf [2] 01 b1 [2] 2a 9d [2] 04 bf [2] 10 a4 [2] 1f be [2] 01 a3 [2] 03 a2 [2] 18 a4 [2] 04 a3 [2] 18 8c }

  condition:
    any of them
}