rule TTP_XOR_QUAD_CurrentVersionRun_abf6 {
  strings:
    $key_abf6 = { f8 99 [2] dc 97 [2] f7 bb [2] d9 99 [2] cd 82 [2] c2 98 [2] dc 85 [2] de 84 [2] c5 82 [2] d9 85 [2] c5 aa }

  condition:
    any of them
}