rule TTP_XOR_QUAD_CurrentVersionRun_a939 {
  strings:
    $key_a939 = { fa 56 [2] de 58 [2] f5 74 [2] db 56 [2] cf 4d [2] c0 57 [2] de 4a [2] dc 4b [2] c7 4d [2] db 4a [2] c7 65 }

  condition:
    any of them
}