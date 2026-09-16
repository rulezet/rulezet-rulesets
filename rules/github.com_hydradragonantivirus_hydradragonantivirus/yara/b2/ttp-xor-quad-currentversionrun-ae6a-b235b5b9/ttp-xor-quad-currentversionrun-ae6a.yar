rule TTP_XOR_QUAD_CurrentVersionRun_ae6a {
  strings:
    $key_ae6a = { fd 05 [2] d9 0b [2] f2 27 [2] dc 05 [2] c8 1e [2] c7 04 [2] d9 19 [2] db 18 [2] c0 1e [2] dc 19 [2] c0 36 }

  condition:
    any of them
}