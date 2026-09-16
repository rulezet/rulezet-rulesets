rule TTP_XOR_QUAD_CurrentVersionRun_26d0 {
  strings:
    $key_26d0 = { 75 bf [2] 51 b1 [2] 7a 9d [2] 54 bf [2] 40 a4 [2] 4f be [2] 51 a3 [2] 53 a2 [2] 48 a4 [2] 54 a3 [2] 48 8c }

  condition:
    any of them
}