rule TTP_XOR_QUAD_CurrentVersionRun_35d0 {
  strings:
    $key_35d0 = { 66 bf [2] 42 b1 [2] 69 9d [2] 47 bf [2] 53 a4 [2] 5c be [2] 42 a3 [2] 40 a2 [2] 5b a4 [2] 47 a3 [2] 5b 8c }

  condition:
    any of them
}