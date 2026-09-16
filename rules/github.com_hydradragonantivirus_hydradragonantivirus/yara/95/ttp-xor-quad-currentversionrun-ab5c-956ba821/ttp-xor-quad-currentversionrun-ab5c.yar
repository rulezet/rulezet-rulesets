rule TTP_XOR_QUAD_CurrentVersionRun_ab5c {
  strings:
    $key_ab5c = { f8 33 [2] dc 3d [2] f7 11 [2] d9 33 [2] cd 28 [2] c2 32 [2] dc 2f [2] de 2e [2] c5 28 [2] d9 2f [2] c5 00 }

  condition:
    any of them
}