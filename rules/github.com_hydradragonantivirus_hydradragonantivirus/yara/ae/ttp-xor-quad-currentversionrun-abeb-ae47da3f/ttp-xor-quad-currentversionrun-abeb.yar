rule TTP_XOR_QUAD_CurrentVersionRun_abeb {
  strings:
    $key_abeb = { f8 84 [2] dc 8a [2] f7 a6 [2] d9 84 [2] cd 9f [2] c2 85 [2] dc 98 [2] de 99 [2] c5 9f [2] d9 98 [2] c5 b7 }

  condition:
    any of them
}