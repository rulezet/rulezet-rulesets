rule TTP_XOR_QUAD_CurrentVersionRun_a94a {
  strings:
    $key_a94a = { fa 25 [2] de 2b [2] f5 07 [2] db 25 [2] cf 3e [2] c0 24 [2] de 39 [2] dc 38 [2] c7 3e [2] db 39 [2] c7 16 }

  condition:
    any of them
}