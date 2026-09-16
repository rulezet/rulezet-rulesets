rule TTP_XOR_QUAD_CurrentVersionRun_a95d {
  strings:
    $key_a95d = { fa 32 [2] de 3c [2] f5 10 [2] db 32 [2] cf 29 [2] c0 33 [2] de 2e [2] dc 2f [2] c7 29 [2] db 2e [2] c7 01 }

  condition:
    any of them
}