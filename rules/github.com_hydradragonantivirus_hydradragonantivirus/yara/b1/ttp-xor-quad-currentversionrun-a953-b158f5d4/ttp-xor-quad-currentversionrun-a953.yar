rule TTP_XOR_QUAD_CurrentVersionRun_a953 {
  strings:
    $key_a953 = { fa 3c [2] de 32 [2] f5 1e [2] db 3c [2] cf 27 [2] c0 3d [2] de 20 [2] dc 21 [2] c7 27 [2] db 20 [2] c7 0f }

  condition:
    any of them
}