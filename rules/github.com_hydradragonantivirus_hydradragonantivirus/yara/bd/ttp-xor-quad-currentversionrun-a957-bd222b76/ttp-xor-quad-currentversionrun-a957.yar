rule TTP_XOR_QUAD_CurrentVersionRun_a957 {
  strings:
    $key_a957 = { fa 38 [2] de 36 [2] f5 1a [2] db 38 [2] cf 23 [2] c0 39 [2] de 24 [2] dc 25 [2] c7 23 [2] db 24 [2] c7 0b }

  condition:
    any of them
}