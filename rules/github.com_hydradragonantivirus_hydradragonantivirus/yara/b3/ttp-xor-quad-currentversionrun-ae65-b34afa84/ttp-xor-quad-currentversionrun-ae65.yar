rule TTP_XOR_QUAD_CurrentVersionRun_ae65 {
  strings:
    $key_ae65 = { fd 0a [2] d9 04 [2] f2 28 [2] dc 0a [2] c8 11 [2] c7 0b [2] d9 16 [2] db 17 [2] c0 11 [2] dc 16 [2] c0 39 }

  condition:
    any of them
}