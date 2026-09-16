rule TTP_XOR_QUAD_CurrentVersionRun_ab24 {
  strings:
    $key_ab24 = { f8 4b [2] dc 45 [2] f7 69 [2] d9 4b [2] cd 50 [2] c2 4a [2] dc 57 [2] de 56 [2] c5 50 [2] d9 57 [2] c5 78 }

  condition:
    any of them
}