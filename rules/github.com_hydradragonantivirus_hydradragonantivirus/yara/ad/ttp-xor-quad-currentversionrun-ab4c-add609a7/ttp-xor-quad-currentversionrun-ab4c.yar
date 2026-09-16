rule TTP_XOR_QUAD_CurrentVersionRun_ab4c {
  strings:
    $key_ab4c = { f8 23 [2] dc 2d [2] f7 01 [2] d9 23 [2] cd 38 [2] c2 22 [2] dc 3f [2] de 3e [2] c5 38 [2] d9 3f [2] c5 10 }

  condition:
    any of them
}