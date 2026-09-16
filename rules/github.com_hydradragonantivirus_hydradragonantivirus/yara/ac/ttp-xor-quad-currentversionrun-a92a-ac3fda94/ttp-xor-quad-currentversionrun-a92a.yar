rule TTP_XOR_QUAD_CurrentVersionRun_a92a {
  strings:
    $key_a92a = { fa 45 [2] de 4b [2] f5 67 [2] db 45 [2] cf 5e [2] c0 44 [2] de 59 [2] dc 58 [2] c7 5e [2] db 59 [2] c7 76 }

  condition:
    any of them
}