rule TTP_XOR_QUAD_CurrentVersionRun_ae35 {
  strings:
    $key_ae35 = { fd 5a [2] d9 54 [2] f2 78 [2] dc 5a [2] c8 41 [2] c7 5b [2] d9 46 [2] db 47 [2] c0 41 [2] dc 46 [2] c0 69 }

  condition:
    any of them
}