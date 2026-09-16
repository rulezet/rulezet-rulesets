rule TTP_XOR_QUAD_CurrentVersionRun_ae59 {
  strings:
    $key_ae59 = { fd 36 [2] d9 38 [2] f2 14 [2] dc 36 [2] c8 2d [2] c7 37 [2] d9 2a [2] db 2b [2] c0 2d [2] dc 2a [2] c0 05 }

  condition:
    any of them
}