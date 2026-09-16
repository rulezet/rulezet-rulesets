rule TTP_XOR_QUAD_CurrentVersionRun_a93e {
  strings:
    $key_a93e = { fa 51 [2] de 5f [2] f5 73 [2] db 51 [2] cf 4a [2] c0 50 [2] de 4d [2] dc 4c [2] c7 4a [2] db 4d [2] c7 62 }

  condition:
    any of them
}