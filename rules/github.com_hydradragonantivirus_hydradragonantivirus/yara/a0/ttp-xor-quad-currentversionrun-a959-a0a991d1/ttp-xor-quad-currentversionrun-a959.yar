rule TTP_XOR_QUAD_CurrentVersionRun_a959 {
  strings:
    $key_a959 = { fa 36 [2] de 38 [2] f5 14 [2] db 36 [2] cf 2d [2] c0 37 [2] de 2a [2] dc 2b [2] c7 2d [2] db 2a [2] c7 05 }

  condition:
    any of them
}