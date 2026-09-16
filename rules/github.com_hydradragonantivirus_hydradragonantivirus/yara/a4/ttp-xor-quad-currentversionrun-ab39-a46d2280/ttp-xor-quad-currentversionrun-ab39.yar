rule TTP_XOR_QUAD_CurrentVersionRun_ab39 {
  strings:
    $key_ab39 = { f8 56 [2] dc 58 [2] f7 74 [2] d9 56 [2] cd 4d [2] c2 57 [2] dc 4a [2] de 4b [2] c5 4d [2] d9 4a [2] c5 65 }

  condition:
    any of them
}