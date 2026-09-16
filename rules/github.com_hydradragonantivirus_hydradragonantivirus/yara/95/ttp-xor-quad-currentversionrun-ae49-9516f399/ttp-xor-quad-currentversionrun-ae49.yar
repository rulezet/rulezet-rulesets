rule TTP_XOR_QUAD_CurrentVersionRun_ae49 {
  strings:
    $key_ae49 = { fd 26 [2] d9 28 [2] f2 04 [2] dc 26 [2] c8 3d [2] c7 27 [2] d9 3a [2] db 3b [2] c0 3d [2] dc 3a [2] c0 15 }

  condition:
    any of them
}