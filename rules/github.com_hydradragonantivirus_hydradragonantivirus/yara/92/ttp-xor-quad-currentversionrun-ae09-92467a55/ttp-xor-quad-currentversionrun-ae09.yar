rule TTP_XOR_QUAD_CurrentVersionRun_ae09 {
  strings:
    $key_ae09 = { fd 66 [2] d9 68 [2] f2 44 [2] dc 66 [2] c8 7d [2] c7 67 [2] d9 7a [2] db 7b [2] c0 7d [2] dc 7a [2] c0 55 }

  condition:
    any of them
}