rule TTP_XOR_QUAD_CurrentVersionRun_ae2c {
  strings:
    $key_ae2c = { fd 43 [2] d9 4d [2] f2 61 [2] dc 43 [2] c8 58 [2] c7 42 [2] d9 5f [2] db 5e [2] c0 58 [2] dc 5f [2] c0 70 }

  condition:
    any of them
}