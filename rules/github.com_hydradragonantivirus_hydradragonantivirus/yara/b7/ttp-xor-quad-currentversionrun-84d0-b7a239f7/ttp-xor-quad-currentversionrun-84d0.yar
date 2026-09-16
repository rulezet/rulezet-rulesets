rule TTP_XOR_QUAD_CurrentVersionRun_84d0 {
  strings:
    $key_84d0 = { d7 bf [2] f3 b1 [2] d8 9d [2] f6 bf [2] e2 a4 [2] ed be [2] f3 a3 [2] f1 a2 [2] ea a4 [2] f6 a3 [2] ea 8c }

  condition:
    any of them
}