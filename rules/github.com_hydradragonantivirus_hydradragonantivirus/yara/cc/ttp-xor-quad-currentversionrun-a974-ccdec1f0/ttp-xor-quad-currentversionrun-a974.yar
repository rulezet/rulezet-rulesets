rule TTP_XOR_QUAD_CurrentVersionRun_a974 {
  strings:
    $key_a974 = { fa 1b [2] de 15 [2] f5 39 [2] db 1b [2] cf 00 [2] c0 1a [2] de 07 [2] dc 06 [2] c7 00 [2] db 07 [2] c7 28 }

  condition:
    any of them
}