rule TTP_XOR_QUAD_CurrentVersionRun_ae1b {
  strings:
    $key_ae1b = { fd 74 [2] d9 7a [2] f2 56 [2] dc 74 [2] c8 6f [2] c7 75 [2] d9 68 [2] db 69 [2] c0 6f [2] dc 68 [2] c0 47 }

  condition:
    any of them
}