rule TTP_XOR_QUAD_CurrentVersionRun_a9ef {
  strings:
    $key_a9ef = { fa 80 [2] de 8e [2] f5 a2 [2] db 80 [2] cf 9b [2] c0 81 [2] de 9c [2] dc 9d [2] c7 9b [2] db 9c [2] c7 b3 }

  condition:
    any of them
}