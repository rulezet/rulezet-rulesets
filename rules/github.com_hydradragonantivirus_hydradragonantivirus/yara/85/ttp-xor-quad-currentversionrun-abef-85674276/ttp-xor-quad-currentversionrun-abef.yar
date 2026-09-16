rule TTP_XOR_QUAD_CurrentVersionRun_abef {
  strings:
    $key_abef = { f8 80 [2] dc 8e [2] f7 a2 [2] d9 80 [2] cd 9b [2] c2 81 [2] dc 9c [2] de 9d [2] c5 9b [2] d9 9c [2] c5 b3 }

  condition:
    any of them
}