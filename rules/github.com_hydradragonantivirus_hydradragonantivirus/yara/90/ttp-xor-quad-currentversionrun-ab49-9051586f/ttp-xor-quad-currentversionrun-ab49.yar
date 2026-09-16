rule TTP_XOR_QUAD_CurrentVersionRun_ab49 {
  strings:
    $key_ab49 = { f8 26 [2] dc 28 [2] f7 04 [2] d9 26 [2] cd 3d [2] c2 27 [2] dc 3a [2] de 3b [2] c5 3d [2] d9 3a [2] c5 15 }

  condition:
    any of them
}