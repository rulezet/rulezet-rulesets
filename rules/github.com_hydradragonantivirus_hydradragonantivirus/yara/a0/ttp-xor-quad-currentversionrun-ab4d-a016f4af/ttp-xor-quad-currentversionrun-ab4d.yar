rule TTP_XOR_QUAD_CurrentVersionRun_ab4d {
  strings:
    $key_ab4d = { f8 22 [2] dc 2c [2] f7 00 [2] d9 22 [2] cd 39 [2] c2 23 [2] dc 3e [2] de 3f [2] c5 39 [2] d9 3e [2] c5 11 }

  condition:
    any of them
}