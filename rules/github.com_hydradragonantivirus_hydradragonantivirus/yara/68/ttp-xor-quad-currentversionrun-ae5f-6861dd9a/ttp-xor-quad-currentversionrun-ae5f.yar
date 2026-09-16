rule TTP_XOR_QUAD_CurrentVersionRun_ae5f {
  strings:
    $key_ae5f = { fd 30 [2] d9 3e [2] f2 12 [2] dc 30 [2] c8 2b [2] c7 31 [2] d9 2c [2] db 2d [2] c0 2b [2] dc 2c [2] c0 03 }

  condition:
    any of them
}