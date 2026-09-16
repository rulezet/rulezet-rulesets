rule TTP_XOR_QUAD_CurrentVersionRun_ab16 {
  strings:
    $key_ab16 = { f8 79 [2] dc 77 [2] f7 5b [2] d9 79 [2] cd 62 [2] c2 78 [2] dc 65 [2] de 64 [2] c5 62 [2] d9 65 [2] c5 4a }

  condition:
    any of them
}