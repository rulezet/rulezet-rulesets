rule TTP_XOR_QUAD_CurrentVersionRun_a95e {
  strings:
    $key_a95e = { fa 31 [2] de 3f [2] f5 13 [2] db 31 [2] cf 2a [2] c0 30 [2] de 2d [2] dc 2c [2] c7 2a [2] db 2d [2] c7 02 }

  condition:
    any of them
}