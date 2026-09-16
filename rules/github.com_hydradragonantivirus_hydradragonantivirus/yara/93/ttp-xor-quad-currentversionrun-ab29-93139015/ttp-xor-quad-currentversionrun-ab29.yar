rule TTP_XOR_QUAD_CurrentVersionRun_ab29 {
  strings:
    $key_ab29 = { f8 46 [2] dc 48 [2] f7 64 [2] d9 46 [2] cd 5d [2] c2 47 [2] dc 5a [2] de 5b [2] c5 5d [2] d9 5a [2] c5 75 }

  condition:
    any of them
}