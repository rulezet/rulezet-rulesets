rule TTP_XOR_QUAD_CurrentVersionRun_ae2b {
  strings:
    $key_ae2b = { fd 44 [2] d9 4a [2] f2 66 [2] dc 44 [2] c8 5f [2] c7 45 [2] d9 58 [2] db 59 [2] c0 5f [2] dc 58 [2] c0 77 }

  condition:
    any of them
}