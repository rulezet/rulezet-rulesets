rule TTP_XOR_QUAD_CurrentVersionRun_32d0 {
  strings:
    $key_32d0 = { 61 bf [2] 45 b1 [2] 6e 9d [2] 40 bf [2] 54 a4 [2] 5b be [2] 45 a3 [2] 47 a2 [2] 5c a4 [2] 40 a3 [2] 5c 8c }

  condition:
    any of them
}