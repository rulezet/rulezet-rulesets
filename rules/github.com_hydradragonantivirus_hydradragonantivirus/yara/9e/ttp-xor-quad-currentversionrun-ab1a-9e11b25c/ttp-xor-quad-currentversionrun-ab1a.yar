rule TTP_XOR_QUAD_CurrentVersionRun_ab1a {
  strings:
    $key_ab1a = { f8 75 [2] dc 7b [2] f7 57 [2] d9 75 [2] cd 6e [2] c2 74 [2] dc 69 [2] de 68 [2] c5 6e [2] d9 69 [2] c5 46 }

  condition:
    any of them
}