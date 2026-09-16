rule TTP_XOR_QUAD_CurrentVersionRun_ab17 {
  strings:
    $key_ab17 = { f8 78 [2] dc 76 [2] f7 5a [2] d9 78 [2] cd 63 [2] c2 79 [2] dc 64 [2] de 65 [2] c5 63 [2] d9 64 [2] c5 4b }

  condition:
    any of them
}