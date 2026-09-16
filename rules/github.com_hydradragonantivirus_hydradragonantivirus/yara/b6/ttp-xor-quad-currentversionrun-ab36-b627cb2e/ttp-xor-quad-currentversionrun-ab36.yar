rule TTP_XOR_QUAD_CurrentVersionRun_ab36 {
  strings:
    $key_ab36 = { f8 59 [2] dc 57 [2] f7 7b [2] d9 59 [2] cd 42 [2] c2 58 [2] dc 45 [2] de 44 [2] c5 42 [2] d9 45 [2] c5 6a }

  condition:
    any of them
}