rule TTP_XOR_QUAD_CurrentVersionRun_ab13 {
  strings:
    $key_ab13 = { f8 7c [2] dc 72 [2] f7 5e [2] d9 7c [2] cd 67 [2] c2 7d [2] dc 60 [2] de 61 [2] c5 67 [2] d9 60 [2] c5 4f }

  condition:
    any of them
}