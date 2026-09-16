rule TTP_XOR_QUAD_CurrentVersionRun_a967 {
  strings:
    $key_a967 = { fa 08 [2] de 06 [2] f5 2a [2] db 08 [2] cf 13 [2] c0 09 [2] de 14 [2] dc 15 [2] c7 13 [2] db 14 [2] c7 3b }

  condition:
    any of them
}