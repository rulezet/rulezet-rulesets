rule TTP_XOR_QUAD_CurrentVersionRun_a940 {
  strings:
    $key_a940 = { fa 2f [2] de 21 [2] f5 0d [2] db 2f [2] cf 34 [2] c0 2e [2] de 33 [2] dc 32 [2] c7 34 [2] db 33 [2] c7 1c }

  condition:
    any of them
}