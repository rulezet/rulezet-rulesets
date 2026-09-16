rule TTP_XOR_QUAD_CurrentVersionRun_ae23 {
  strings:
    $key_ae23 = { fd 4c [2] d9 42 [2] f2 6e [2] dc 4c [2] c8 57 [2] c7 4d [2] d9 50 [2] db 51 [2] c0 57 [2] dc 50 [2] c0 7f }

  condition:
    any of them
}