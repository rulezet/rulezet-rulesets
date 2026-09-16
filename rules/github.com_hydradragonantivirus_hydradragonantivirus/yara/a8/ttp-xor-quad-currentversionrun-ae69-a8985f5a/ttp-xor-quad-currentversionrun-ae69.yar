rule TTP_XOR_QUAD_CurrentVersionRun_ae69 {
  strings:
    $key_ae69 = { fd 06 [2] d9 08 [2] f2 24 [2] dc 06 [2] c8 1d [2] c7 07 [2] d9 1a [2] db 1b [2] c0 1d [2] dc 1a [2] c0 35 }

  condition:
    any of them
}