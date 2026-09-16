rule TTP_XOR_QUAD_CurrentVersionRun_a978 {
  strings:
    $key_a978 = { fa 17 [2] de 19 [2] f5 35 [2] db 17 [2] cf 0c [2] c0 16 [2] de 0b [2] dc 0a [2] c7 0c [2] db 0b [2] c7 24 }

  condition:
    any of them
}