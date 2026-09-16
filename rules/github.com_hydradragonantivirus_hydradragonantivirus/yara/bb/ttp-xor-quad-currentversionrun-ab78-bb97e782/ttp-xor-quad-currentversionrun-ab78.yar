rule TTP_XOR_QUAD_CurrentVersionRun_ab78 {
  strings:
    $key_ab78 = { f8 17 [2] dc 19 [2] f7 35 [2] d9 17 [2] cd 0c [2] c2 16 [2] dc 0b [2] de 0a [2] c5 0c [2] d9 0b [2] c5 24 }

  condition:
    any of them
}