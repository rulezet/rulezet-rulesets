rule TTP_XOR_QUAD_CurrentVersionRun_8bd0 {
  strings:
    $key_8bd0 = { d8 bf [2] fc b1 [2] d7 9d [2] f9 bf [2] ed a4 [2] e2 be [2] fc a3 [2] fe a2 [2] e5 a4 [2] f9 a3 [2] e5 8c }

  condition:
    any of them
}