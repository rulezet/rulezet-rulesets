rule TTP_XOR_QUAD_CurrentVersionRun_ae53 {
  strings:
    $key_ae53 = { fd 3c [2] d9 32 [2] f2 1e [2] dc 3c [2] c8 27 [2] c7 3d [2] d9 20 [2] db 21 [2] c0 27 [2] dc 20 [2] c0 0f }

  condition:
    any of them
}