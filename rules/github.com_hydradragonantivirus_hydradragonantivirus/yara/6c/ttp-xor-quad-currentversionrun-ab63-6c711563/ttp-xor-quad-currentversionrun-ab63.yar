rule TTP_XOR_QUAD_CurrentVersionRun_ab63 {
  strings:
    $key_ab63 = { f8 0c [2] dc 02 [2] f7 2e [2] d9 0c [2] cd 17 [2] c2 0d [2] dc 10 [2] de 11 [2] c5 17 [2] d9 10 [2] c5 3f }

  condition:
    any of them
}