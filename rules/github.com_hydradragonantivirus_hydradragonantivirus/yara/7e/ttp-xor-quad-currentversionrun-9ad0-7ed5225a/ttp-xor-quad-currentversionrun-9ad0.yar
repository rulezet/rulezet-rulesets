rule TTP_XOR_QUAD_CurrentVersionRun_9ad0 {
  strings:
    $key_9ad0 = { c9 bf [2] ed b1 [2] c6 9d [2] e8 bf [2] fc a4 [2] f3 be [2] ed a3 [2] ef a2 [2] f4 a4 [2] e8 a3 [2] f4 8c }

  condition:
    any of them
}