rule TTP_XOR_QUAD_CurrentVersionRun_a95a {
  strings:
    $key_a95a = { fa 35 [2] de 3b [2] f5 17 [2] db 35 [2] cf 2e [2] c0 34 [2] de 29 [2] dc 28 [2] c7 2e [2] db 29 [2] c7 06 }

  condition:
    any of them
}