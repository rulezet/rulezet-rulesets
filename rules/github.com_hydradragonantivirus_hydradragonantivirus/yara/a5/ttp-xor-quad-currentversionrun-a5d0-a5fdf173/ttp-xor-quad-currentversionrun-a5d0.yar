rule TTP_XOR_QUAD_CurrentVersionRun_a5d0 {
  strings:
    $key_a5d0 = { f6 bf [2] d2 b1 [2] f9 9d [2] d7 bf [2] c3 a4 [2] cc be [2] d2 a3 [2] d0 a2 [2] cb a4 [2] d7 a3 [2] cb 8c }

  condition:
    any of them
}