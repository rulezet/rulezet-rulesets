rule TTP_XOR_QUAD_CurrentVersionRun_a9e9 {
  strings:
    $key_a9e9 = { fa 86 [2] de 88 [2] f5 a4 [2] db 86 [2] cf 9d [2] c0 87 [2] de 9a [2] dc 9b [2] c7 9d [2] db 9a [2] c7 b5 }

  condition:
    any of them
}