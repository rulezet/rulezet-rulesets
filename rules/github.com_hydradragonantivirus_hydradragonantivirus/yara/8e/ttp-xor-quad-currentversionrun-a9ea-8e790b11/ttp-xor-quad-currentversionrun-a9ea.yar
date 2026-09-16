rule TTP_XOR_QUAD_CurrentVersionRun_a9ea {
  strings:
    $key_a9ea = { fa 85 [2] de 8b [2] f5 a7 [2] db 85 [2] cf 9e [2] c0 84 [2] de 99 [2] dc 98 [2] c7 9e [2] db 99 [2] c7 b6 }

  condition:
    any of them
}