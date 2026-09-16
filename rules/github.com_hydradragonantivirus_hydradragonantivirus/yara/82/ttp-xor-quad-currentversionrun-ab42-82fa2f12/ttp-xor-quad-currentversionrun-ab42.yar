rule TTP_XOR_QUAD_CurrentVersionRun_ab42 {
  strings:
    $key_ab42 = { f8 2d [2] dc 23 [2] f7 0f [2] d9 2d [2] cd 36 [2] c2 2c [2] dc 31 [2] de 30 [2] c5 36 [2] d9 31 [2] c5 1e }

  condition:
    any of them
}