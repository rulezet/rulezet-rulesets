rule TTP_XOR_QUAD_CurrentVersionRun_ae7d {
  strings:
    $key_ae7d = { fd 12 [2] d9 1c [2] f2 30 [2] dc 12 [2] c8 09 [2] c7 13 [2] d9 0e [2] db 0f [2] c0 09 [2] dc 0e [2] c0 21 }

  condition:
    any of them
}