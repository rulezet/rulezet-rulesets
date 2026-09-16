rule TTP_XOR_QUAD_CurrentVersionRun_86d0 {
  strings:
    $key_86d0 = { d5 bf [2] f1 b1 [2] da 9d [2] f4 bf [2] e0 a4 [2] ef be [2] f1 a3 [2] f3 a2 [2] e8 a4 [2] f4 a3 [2] e8 8c }

  condition:
    any of them
}