rule TTP_XOR_QUAD_CurrentVersionRun_ae61 {
  strings:
    $key_ae61 = { fd 0e [2] d9 00 [2] f2 2c [2] dc 0e [2] c8 15 [2] c7 0f [2] d9 12 [2] db 13 [2] c0 15 [2] dc 12 [2] c0 3d }

  condition:
    any of them
}