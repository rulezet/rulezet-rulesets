rule TTP_XOR_QUAD_CurrentVersionRun_a9fd {
  strings:
    $key_a9fd = { fa 92 [2] de 9c [2] f5 b0 [2] db 92 [2] cf 89 [2] c0 93 [2] de 8e [2] dc 8f [2] c7 89 [2] db 8e [2] c7 a1 }

  condition:
    any of them
}