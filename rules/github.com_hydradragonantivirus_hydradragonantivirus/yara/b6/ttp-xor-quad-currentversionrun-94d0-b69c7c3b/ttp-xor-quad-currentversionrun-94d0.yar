rule TTP_XOR_QUAD_CurrentVersionRun_94d0 {
  strings:
    $key_94d0 = { c7 bf [2] e3 b1 [2] c8 9d [2] e6 bf [2] f2 a4 [2] fd be [2] e3 a3 [2] e1 a2 [2] fa a4 [2] e6 a3 [2] fa 8c }

  condition:
    any of them
}