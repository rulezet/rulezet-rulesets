rule TTP_XOR_QUAD_CurrentVersionRun_ab2e {
  strings:
    $key_ab2e = { f8 41 [2] dc 4f [2] f7 63 [2] d9 41 [2] cd 5a [2] c2 40 [2] dc 5d [2] de 5c [2] c5 5a [2] d9 5d [2] c5 72 }

  condition:
    any of them
}