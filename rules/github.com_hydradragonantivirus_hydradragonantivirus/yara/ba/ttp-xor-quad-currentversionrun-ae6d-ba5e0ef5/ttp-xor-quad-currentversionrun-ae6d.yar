rule TTP_XOR_QUAD_CurrentVersionRun_ae6d {
  strings:
    $key_ae6d = { fd 02 [2] d9 0c [2] f2 20 [2] dc 02 [2] c8 19 [2] c7 03 [2] d9 1e [2] db 1f [2] c0 19 [2] dc 1e [2] c0 31 }

  condition:
    any of them
}