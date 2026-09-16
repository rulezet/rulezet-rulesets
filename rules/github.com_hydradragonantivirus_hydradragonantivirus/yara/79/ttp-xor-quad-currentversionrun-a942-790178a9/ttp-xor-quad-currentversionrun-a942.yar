rule TTP_XOR_QUAD_CurrentVersionRun_a942 {
  strings:
    $key_a942 = { fa 2d [2] de 23 [2] f5 0f [2] db 2d [2] cf 36 [2] c0 2c [2] de 31 [2] dc 30 [2] c7 36 [2] db 31 [2] c7 1e }

  condition:
    any of them
}