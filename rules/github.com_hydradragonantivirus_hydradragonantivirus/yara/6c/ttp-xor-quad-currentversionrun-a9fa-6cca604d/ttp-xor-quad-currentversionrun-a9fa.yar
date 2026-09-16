rule TTP_XOR_QUAD_CurrentVersionRun_a9fa {
  strings:
    $key_a9fa = { fa 95 [2] de 9b [2] f5 b7 [2] db 95 [2] cf 8e [2] c0 94 [2] de 89 [2] dc 88 [2] c7 8e [2] db 89 [2] c7 a6 }

  condition:
    any of them
}