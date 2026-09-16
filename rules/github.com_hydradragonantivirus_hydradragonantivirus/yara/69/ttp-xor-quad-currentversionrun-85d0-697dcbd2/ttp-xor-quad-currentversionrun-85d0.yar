rule TTP_XOR_QUAD_CurrentVersionRun_85d0 {
  strings:
    $key_85d0 = { d6 bf [2] f2 b1 [2] d9 9d [2] f7 bf [2] e3 a4 [2] ec be [2] f2 a3 [2] f0 a2 [2] eb a4 [2] f7 a3 [2] eb 8c }

  condition:
    any of them
}