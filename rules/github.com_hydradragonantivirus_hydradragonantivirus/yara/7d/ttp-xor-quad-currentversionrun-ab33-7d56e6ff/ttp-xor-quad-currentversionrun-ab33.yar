rule TTP_XOR_QUAD_CurrentVersionRun_ab33 {
  strings:
    $key_ab33 = { f8 5c [2] dc 52 [2] f7 7e [2] d9 5c [2] cd 47 [2] c2 5d [2] dc 40 [2] de 41 [2] c5 47 [2] d9 40 [2] c5 6f }

  condition:
    any of them
}