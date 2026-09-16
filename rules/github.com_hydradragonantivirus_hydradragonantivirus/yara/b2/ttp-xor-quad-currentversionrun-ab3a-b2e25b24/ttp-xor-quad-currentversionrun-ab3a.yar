rule TTP_XOR_QUAD_CurrentVersionRun_ab3a {
  strings:
    $key_ab3a = { f8 55 [2] dc 5b [2] f7 77 [2] d9 55 [2] cd 4e [2] c2 54 [2] dc 49 [2] de 48 [2] c5 4e [2] d9 49 [2] c5 66 }

  condition:
    any of them
}