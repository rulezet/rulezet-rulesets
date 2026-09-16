rule TTP_XOR_QUAD_CurrentVersionRun_abf9 {
  strings:
    $key_abf9 = { f8 96 [2] dc 98 [2] f7 b4 [2] d9 96 [2] cd 8d [2] c2 97 [2] dc 8a [2] de 8b [2] c5 8d [2] d9 8a [2] c5 a5 }

  condition:
    any of them
}