rule TTP_XOR_QUAD_CurrentVersionRun_ae5a {
  strings:
    $key_ae5a = { fd 35 [2] d9 3b [2] f2 17 [2] dc 35 [2] c8 2e [2] c7 34 [2] d9 29 [2] db 28 [2] c0 2e [2] dc 29 [2] c0 06 }

  condition:
    any of them
}