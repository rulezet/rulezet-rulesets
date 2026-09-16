rule TTP_XOR_QUAD_CurrentVersionRun_b0d0 {
  strings:
    $key_b0d0 = { e3 bf [2] c7 b1 [2] ec 9d [2] c2 bf [2] d6 a4 [2] d9 be [2] c7 a3 [2] c5 a2 [2] de a4 [2] c2 a3 [2] de 8c }

  condition:
    any of them
}