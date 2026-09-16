rule TTP_XOR_QUAD_CurrentVersionRun_a968 {
  strings:
    $key_a968 = { fa 07 [2] de 09 [2] f5 25 [2] db 07 [2] cf 1c [2] c0 06 [2] de 1b [2] dc 1a [2] c7 1c [2] db 1b [2] c7 34 }

  condition:
    any of them
}