rule TTP_XOR_QUAD_CurrentVersionRun_ae0b {
  strings:
    $key_ae0b = { fd 64 [2] d9 6a [2] f2 46 [2] dc 64 [2] c8 7f [2] c7 65 [2] d9 78 [2] db 79 [2] c0 7f [2] dc 78 [2] c0 57 }

  condition:
    any of them
}