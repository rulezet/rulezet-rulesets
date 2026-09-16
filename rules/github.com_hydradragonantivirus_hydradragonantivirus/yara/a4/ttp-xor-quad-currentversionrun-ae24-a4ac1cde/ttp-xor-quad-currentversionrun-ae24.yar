rule TTP_XOR_QUAD_CurrentVersionRun_ae24 {
  strings:
    $key_ae24 = { fd 4b [2] d9 45 [2] f2 69 [2] dc 4b [2] c8 50 [2] c7 4a [2] d9 57 [2] db 56 [2] c0 50 [2] dc 57 [2] c0 78 }

  condition:
    any of them
}