rule TTP_XOR_QUAD_CurrentVersionRun_a923 {
  strings:
    $key_a923 = { fa 4c [2] de 42 [2] f5 6e [2] db 4c [2] cf 57 [2] c0 4d [2] de 50 [2] dc 51 [2] c7 57 [2] db 50 [2] c7 7f }

  condition:
    any of them
}