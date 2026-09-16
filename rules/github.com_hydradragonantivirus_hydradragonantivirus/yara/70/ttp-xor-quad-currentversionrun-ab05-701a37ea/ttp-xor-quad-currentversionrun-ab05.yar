rule TTP_XOR_QUAD_CurrentVersionRun_ab05 {
  strings:
    $key_ab05 = { f8 6a [2] dc 64 [2] f7 48 [2] d9 6a [2] cd 71 [2] c2 6b [2] dc 76 [2] de 77 [2] c5 71 [2] d9 76 [2] c5 59 }

  condition:
    any of them
}