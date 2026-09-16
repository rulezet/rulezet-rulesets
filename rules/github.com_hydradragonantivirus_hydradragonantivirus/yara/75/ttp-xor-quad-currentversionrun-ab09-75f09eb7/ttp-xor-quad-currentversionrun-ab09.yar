rule TTP_XOR_QUAD_CurrentVersionRun_ab09 {
  strings:
    $key_ab09 = { f8 66 [2] dc 68 [2] f7 44 [2] d9 66 [2] cd 7d [2] c2 67 [2] dc 7a [2] de 7b [2] c5 7d [2] d9 7a [2] c5 55 }

  condition:
    any of them
}