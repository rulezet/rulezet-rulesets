rule TTP_XOR_QUAD_CurrentVersionRun_abf7 {
  strings:
    $key_abf7 = { f8 98 [2] dc 96 [2] f7 ba [2] d9 98 [2] cd 83 [2] c2 99 [2] dc 84 [2] de 85 [2] c5 83 [2] d9 84 [2] c5 ab }

  condition:
    any of them
}