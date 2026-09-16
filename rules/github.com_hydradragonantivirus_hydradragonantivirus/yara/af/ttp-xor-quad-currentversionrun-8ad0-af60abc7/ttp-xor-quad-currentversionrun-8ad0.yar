rule TTP_XOR_QUAD_CurrentVersionRun_8ad0 {
  strings:
    $key_8ad0 = { d9 bf [2] fd b1 [2] d6 9d [2] f8 bf [2] ec a4 [2] e3 be [2] fd a3 [2] ff a2 [2] e4 a4 [2] f8 a3 [2] e4 8c }

  condition:
    any of them
}