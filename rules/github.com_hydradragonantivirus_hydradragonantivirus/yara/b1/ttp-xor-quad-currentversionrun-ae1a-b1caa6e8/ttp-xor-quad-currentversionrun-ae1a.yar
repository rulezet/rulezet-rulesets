rule TTP_XOR_QUAD_CurrentVersionRun_ae1a {
  strings:
    $key_ae1a = { fd 75 [2] d9 7b [2] f2 57 [2] dc 75 [2] c8 6e [2] c7 74 [2] d9 69 [2] db 68 [2] c0 6e [2] dc 69 [2] c0 46 }

  condition:
    any of them
}