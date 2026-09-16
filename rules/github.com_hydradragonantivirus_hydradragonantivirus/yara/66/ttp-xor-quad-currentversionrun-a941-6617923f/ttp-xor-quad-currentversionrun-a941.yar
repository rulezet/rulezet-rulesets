rule TTP_XOR_QUAD_CurrentVersionRun_a941 {
  strings:
    $key_a941 = { fa 2e [2] de 20 [2] f5 0c [2] db 2e [2] cf 35 [2] c0 2f [2] de 32 [2] dc 33 [2] c7 35 [2] db 32 [2] c7 1d }

  condition:
    any of them
}