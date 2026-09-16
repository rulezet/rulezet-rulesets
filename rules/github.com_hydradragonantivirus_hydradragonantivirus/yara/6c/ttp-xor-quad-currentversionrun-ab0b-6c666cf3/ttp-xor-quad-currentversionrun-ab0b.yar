rule TTP_XOR_QUAD_CurrentVersionRun_ab0b {
  strings:
    $key_ab0b = { f8 64 [2] dc 6a [2] f7 46 [2] d9 64 [2] cd 7f [2] c2 65 [2] dc 78 [2] de 79 [2] c5 7f [2] d9 78 [2] c5 57 }

  condition:
    any of them
}