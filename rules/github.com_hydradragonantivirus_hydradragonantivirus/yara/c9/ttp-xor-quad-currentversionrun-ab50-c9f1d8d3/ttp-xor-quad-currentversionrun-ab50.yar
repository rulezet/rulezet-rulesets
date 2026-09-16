rule TTP_XOR_QUAD_CurrentVersionRun_ab50 {
  strings:
    $key_ab50 = { f8 3f [2] dc 31 [2] f7 1d [2] d9 3f [2] cd 24 [2] c2 3e [2] dc 23 [2] de 22 [2] c5 24 [2] d9 23 [2] c5 0c }

  condition:
    any of them
}