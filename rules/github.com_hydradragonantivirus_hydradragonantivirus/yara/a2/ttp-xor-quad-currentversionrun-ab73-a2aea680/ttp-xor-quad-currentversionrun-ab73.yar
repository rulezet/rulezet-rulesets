rule TTP_XOR_QUAD_CurrentVersionRun_ab73 {
  strings:
    $key_ab73 = { f8 1c [2] dc 12 [2] f7 3e [2] d9 1c [2] cd 07 [2] c2 1d [2] dc 00 [2] de 01 [2] c5 07 [2] d9 00 [2] c5 2f }

  condition:
    any of them
}