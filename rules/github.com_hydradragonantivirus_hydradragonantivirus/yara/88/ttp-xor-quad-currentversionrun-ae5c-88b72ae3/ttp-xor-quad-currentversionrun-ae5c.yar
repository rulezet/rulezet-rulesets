rule TTP_XOR_QUAD_CurrentVersionRun_ae5c {
  strings:
    $key_ae5c = { fd 33 [2] d9 3d [2] f2 11 [2] dc 33 [2] c8 28 [2] c7 32 [2] d9 2f [2] db 2e [2] c0 28 [2] dc 2f [2] c0 00 }

  condition:
    any of them
}