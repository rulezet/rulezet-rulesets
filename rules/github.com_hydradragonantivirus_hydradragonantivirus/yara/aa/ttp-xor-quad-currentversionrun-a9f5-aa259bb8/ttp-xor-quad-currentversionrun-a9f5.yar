rule TTP_XOR_QUAD_CurrentVersionRun_a9f5 {
  strings:
    $key_a9f5 = { fa 9a [2] de 94 [2] f5 b8 [2] db 9a [2] cf 81 [2] c0 9b [2] de 86 [2] dc 87 [2] c7 81 [2] db 86 [2] c7 a9 }

  condition:
    any of them
}