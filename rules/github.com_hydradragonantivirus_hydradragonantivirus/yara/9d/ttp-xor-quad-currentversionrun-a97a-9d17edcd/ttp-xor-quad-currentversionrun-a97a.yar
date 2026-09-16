rule TTP_XOR_QUAD_CurrentVersionRun_a97a {
  strings:
    $key_a97a = { fa 15 [2] de 1b [2] f5 37 [2] db 15 [2] cf 0e [2] c0 14 [2] de 09 [2] dc 08 [2] c7 0e [2] db 09 [2] c7 26 }

  condition:
    any of them
}