rule TTP_XOR_QUAD_CurrentVersionRun_ae07 {
  strings:
    $key_ae07 = { fd 68 [2] d9 66 [2] f2 4a [2] dc 68 [2] c8 73 [2] c7 69 [2] d9 74 [2] db 75 [2] c0 73 [2] dc 74 [2] c0 5b }

  condition:
    any of them
}