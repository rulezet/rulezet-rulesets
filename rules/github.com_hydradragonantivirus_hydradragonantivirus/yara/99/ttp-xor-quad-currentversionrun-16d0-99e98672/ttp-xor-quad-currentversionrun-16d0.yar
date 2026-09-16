rule TTP_XOR_QUAD_CurrentVersionRun_16d0 {
  strings:
    $key_16d0 = { 45 bf [2] 61 b1 [2] 4a 9d [2] 64 bf [2] 70 a4 [2] 7f be [2] 61 a3 [2] 63 a2 [2] 78 a4 [2] 64 a3 [2] 78 8c }

  condition:
    any of them
}