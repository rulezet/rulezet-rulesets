rule TTP_XOR_QUAD_CurrentVersionRun_abee {
  strings:
    $key_abee = { f8 81 [2] dc 8f [2] f7 a3 [2] d9 81 [2] cd 9a [2] c2 80 [2] dc 9d [2] de 9c [2] c5 9a [2] d9 9d [2] c5 b2 }

  condition:
    any of them
}