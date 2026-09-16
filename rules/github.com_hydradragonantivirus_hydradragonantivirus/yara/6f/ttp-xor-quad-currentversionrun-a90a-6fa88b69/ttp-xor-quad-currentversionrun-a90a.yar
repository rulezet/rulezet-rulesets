rule TTP_XOR_QUAD_CurrentVersionRun_a90a {
  strings:
    $key_a90a = { fa 65 [2] de 6b [2] f5 47 [2] db 65 [2] cf 7e [2] c0 64 [2] de 79 [2] dc 78 [2] c7 7e [2] db 79 [2] c7 56 }

  condition:
    any of them
}