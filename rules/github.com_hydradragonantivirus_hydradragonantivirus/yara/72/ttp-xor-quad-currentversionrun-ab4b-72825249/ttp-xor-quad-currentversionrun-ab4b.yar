rule TTP_XOR_QUAD_CurrentVersionRun_ab4b {
  strings:
    $key_ab4b = { f8 24 [2] dc 2a [2] f7 06 [2] d9 24 [2] cd 3f [2] c2 25 [2] dc 38 [2] de 39 [2] c5 3f [2] d9 38 [2] c5 17 }

  condition:
    any of them
}