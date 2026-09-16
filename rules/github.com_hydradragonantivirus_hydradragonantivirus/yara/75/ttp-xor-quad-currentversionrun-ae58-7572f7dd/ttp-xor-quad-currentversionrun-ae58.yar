rule TTP_XOR_QUAD_CurrentVersionRun_ae58 {
  strings:
    $key_ae58 = { fd 37 [2] d9 39 [2] f2 15 [2] dc 37 [2] c8 2c [2] c7 36 [2] d9 2b [2] db 2a [2] c0 2c [2] dc 2b [2] c0 04 }

  condition:
    any of them
}