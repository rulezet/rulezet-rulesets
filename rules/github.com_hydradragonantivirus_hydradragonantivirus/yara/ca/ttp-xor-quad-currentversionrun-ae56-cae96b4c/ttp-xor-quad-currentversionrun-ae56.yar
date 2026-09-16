rule TTP_XOR_QUAD_CurrentVersionRun_ae56 {
  strings:
    $key_ae56 = { fd 39 [2] d9 37 [2] f2 1b [2] dc 39 [2] c8 22 [2] c7 38 [2] d9 25 [2] db 24 [2] c0 22 [2] dc 25 [2] c0 0a }

  condition:
    any of them
}