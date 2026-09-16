rule TTP_XOR_QUAD_CurrentVersionRun_a954 {
  strings:
    $key_a954 = { fa 3b [2] de 35 [2] f5 19 [2] db 3b [2] cf 20 [2] c0 3a [2] de 27 [2] dc 26 [2] c7 20 [2] db 27 [2] c7 08 }

  condition:
    any of them
}