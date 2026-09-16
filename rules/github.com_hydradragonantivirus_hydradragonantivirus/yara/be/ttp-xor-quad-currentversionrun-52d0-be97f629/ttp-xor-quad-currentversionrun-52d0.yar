rule TTP_XOR_QUAD_CurrentVersionRun_52d0 {
  strings:
    $key_52d0 = { 01 bf [2] 25 b1 [2] 0e 9d [2] 20 bf [2] 34 a4 [2] 3b be [2] 25 a3 [2] 27 a2 [2] 3c a4 [2] 20 a3 [2] 3c 8c }

  condition:
    any of them
}