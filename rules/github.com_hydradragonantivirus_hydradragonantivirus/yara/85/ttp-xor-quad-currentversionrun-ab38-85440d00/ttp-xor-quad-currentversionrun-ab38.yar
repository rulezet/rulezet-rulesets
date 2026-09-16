rule TTP_XOR_QUAD_CurrentVersionRun_ab38 {
  strings:
    $key_ab38 = { f8 57 [2] dc 59 [2] f7 75 [2] d9 57 [2] cd 4c [2] c2 56 [2] dc 4b [2] de 4a [2] c5 4c [2] d9 4b [2] c5 64 }

  condition:
    any of them
}