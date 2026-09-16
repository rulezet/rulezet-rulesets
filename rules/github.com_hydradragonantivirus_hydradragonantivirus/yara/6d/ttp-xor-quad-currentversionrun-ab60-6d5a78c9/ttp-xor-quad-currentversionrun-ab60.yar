rule TTP_XOR_QUAD_CurrentVersionRun_ab60 {
  strings:
    $key_ab60 = { f8 0f [2] dc 01 [2] f7 2d [2] d9 0f [2] cd 14 [2] c2 0e [2] dc 13 [2] de 12 [2] c5 14 [2] d9 13 [2] c5 3c }

  condition:
    any of them
}