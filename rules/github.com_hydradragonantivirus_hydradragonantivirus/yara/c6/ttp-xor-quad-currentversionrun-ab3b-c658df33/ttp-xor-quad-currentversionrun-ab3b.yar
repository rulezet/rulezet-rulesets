rule TTP_XOR_QUAD_CurrentVersionRun_ab3b {
  strings:
    $key_ab3b = { f8 54 [2] dc 5a [2] f7 76 [2] d9 54 [2] cd 4f [2] c2 55 [2] dc 48 [2] de 49 [2] c5 4f [2] d9 48 [2] c5 67 }

  condition:
    any of them
}