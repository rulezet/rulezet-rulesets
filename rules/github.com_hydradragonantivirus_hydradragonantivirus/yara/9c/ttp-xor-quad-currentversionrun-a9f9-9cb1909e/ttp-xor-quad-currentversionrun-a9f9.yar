rule TTP_XOR_QUAD_CurrentVersionRun_a9f9 {
  strings:
    $key_a9f9 = { fa 96 [2] de 98 [2] f5 b4 [2] db 96 [2] cf 8d [2] c0 97 [2] de 8a [2] dc 8b [2] c7 8d [2] db 8a [2] c7 a5 }

  condition:
    any of them
}