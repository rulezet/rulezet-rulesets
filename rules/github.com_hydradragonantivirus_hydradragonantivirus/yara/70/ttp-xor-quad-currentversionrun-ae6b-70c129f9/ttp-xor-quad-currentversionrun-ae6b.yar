rule TTP_XOR_QUAD_CurrentVersionRun_ae6b {
  strings:
    $key_ae6b = { fd 04 [2] d9 0a [2] f2 26 [2] dc 04 [2] c8 1f [2] c7 05 [2] d9 18 [2] db 19 [2] c0 1f [2] dc 18 [2] c0 37 }

  condition:
    any of them
}