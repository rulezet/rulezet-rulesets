rule TTP_XOR_QUAD_CurrentVersionRun_83d0 {
  strings:
    $key_83d0 = { d0 bf [2] f4 b1 [2] df 9d [2] f1 bf [2] e5 a4 [2] ea be [2] f4 a3 [2] f6 a2 [2] ed a4 [2] f1 a3 [2] ed 8c }

  condition:
    any of them
}