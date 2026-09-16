rule TTP_XOR_QUAD_CurrentVersionRun_a975 {
  strings:
    $key_a975 = { fa 1a [2] de 14 [2] f5 38 [2] db 1a [2] cf 01 [2] c0 1b [2] de 06 [2] dc 07 [2] c7 01 [2] db 06 [2] c7 29 }

  condition:
    any of them
}