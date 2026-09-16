rule TTP_XOR_QUAD_CurrentVersionRun_a925 {
  strings:
    $key_a925 = { fa 4a [2] de 44 [2] f5 68 [2] db 4a [2] cf 51 [2] c0 4b [2] de 56 [2] dc 57 [2] c7 51 [2] db 56 [2] c7 79 }

  condition:
    any of them
}