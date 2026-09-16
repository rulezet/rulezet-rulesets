rule TTP_XOR_QUAD_CurrentVersionRun_ae41 {
  strings:
    $key_ae41 = { fd 2e [2] d9 20 [2] f2 0c [2] dc 2e [2] c8 35 [2] c7 2f [2] d9 32 [2] db 33 [2] c0 35 [2] dc 32 [2] c0 1d }

  condition:
    any of them
}