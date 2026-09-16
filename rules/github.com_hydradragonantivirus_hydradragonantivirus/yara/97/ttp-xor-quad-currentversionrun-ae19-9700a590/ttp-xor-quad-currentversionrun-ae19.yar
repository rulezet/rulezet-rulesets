rule TTP_XOR_QUAD_CurrentVersionRun_ae19 {
  strings:
    $key_ae19 = { fd 76 [2] d9 78 [2] f2 54 [2] dc 76 [2] c8 6d [2] c7 77 [2] d9 6a [2] db 6b [2] c0 6d [2] dc 6a [2] c0 45 }

  condition:
    any of them
}