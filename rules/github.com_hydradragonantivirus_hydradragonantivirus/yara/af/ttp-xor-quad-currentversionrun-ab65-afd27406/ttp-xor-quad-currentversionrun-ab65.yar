rule TTP_XOR_QUAD_CurrentVersionRun_ab65 {
  strings:
    $key_ab65 = { f8 0a [2] dc 04 [2] f7 28 [2] d9 0a [2] cd 11 [2] c2 0b [2] dc 16 [2] de 17 [2] c5 11 [2] d9 16 [2] c5 39 }

  condition:
    any of them
}