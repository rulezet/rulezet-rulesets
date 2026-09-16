rule TTP_XOR_QUAD_CurrentVersionRun_a966 {
  strings:
    $key_a966 = { fa 09 [2] de 07 [2] f5 2b [2] db 09 [2] cf 12 [2] c0 08 [2] de 15 [2] dc 14 [2] c7 12 [2] db 15 [2] c7 3a }

  condition:
    any of them
}