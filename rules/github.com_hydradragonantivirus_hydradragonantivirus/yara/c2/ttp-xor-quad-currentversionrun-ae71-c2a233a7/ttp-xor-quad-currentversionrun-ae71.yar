rule TTP_XOR_QUAD_CurrentVersionRun_ae71 {
  strings:
    $key_ae71 = { fd 1e [2] d9 10 [2] f2 3c [2] dc 1e [2] c8 05 [2] c7 1f [2] d9 02 [2] db 03 [2] c0 05 [2] dc 02 [2] c0 2d }

  condition:
    any of them
}