rule TTP_XOR_QUAD_CurrentVersionRun_a903 {
  strings:
    $key_a903 = { fa 6c [2] de 62 [2] f5 4e [2] db 6c [2] cf 77 [2] c0 6d [2] de 70 [2] dc 71 [2] c7 77 [2] db 70 [2] c7 5f }

  condition:
    any of them
}