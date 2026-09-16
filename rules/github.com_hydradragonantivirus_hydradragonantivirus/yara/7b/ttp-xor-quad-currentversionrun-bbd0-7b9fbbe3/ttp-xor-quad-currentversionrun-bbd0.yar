rule TTP_XOR_QUAD_CurrentVersionRun_bbd0 {
  strings:
    $key_bbd0 = { e8 bf [2] cc b1 [2] e7 9d [2] c9 bf [2] dd a4 [2] d2 be [2] cc a3 [2] ce a2 [2] d5 a4 [2] c9 a3 [2] d5 8c }

  condition:
    any of them
}