rule TTP_XOR_QUAD_CurrentVersionRun_abe7 {
  strings:
    $key_abe7 = { f8 88 [2] dc 86 [2] f7 aa [2] d9 88 [2] cd 93 [2] c2 89 [2] dc 94 [2] de 95 [2] c5 93 [2] d9 94 [2] c5 bb }

  condition:
    any of them
}