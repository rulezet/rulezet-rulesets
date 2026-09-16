rule TTP_XOR_QUAD_CurrentVersionRun_b4f2 {
  strings:
    $key_b4f2 = { e7 9d [2] c3 93 [2] e8 bf [2] c6 9d [2] d2 86 [2] dd 9c [2] c3 81 [2] c1 80 [2] da 86 [2] c6 81 [2] da ae }

  condition:
    any of them
}