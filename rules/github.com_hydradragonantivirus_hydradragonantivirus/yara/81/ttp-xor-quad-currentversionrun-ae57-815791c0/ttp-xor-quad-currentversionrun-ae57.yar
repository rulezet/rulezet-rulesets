rule TTP_XOR_QUAD_CurrentVersionRun_ae57 {
  strings:
    $key_ae57 = { fd 38 [2] d9 36 [2] f2 1a [2] dc 38 [2] c8 23 [2] c7 39 [2] d9 24 [2] db 25 [2] c0 23 [2] dc 24 [2] c0 0b }

  condition:
    any of them
}