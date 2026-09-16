rule TTP_XOR_QUAD_CurrentVersionRun_ae66 {
  strings:
    $key_ae66 = { fd 09 [2] d9 07 [2] f2 2b [2] dc 09 [2] c8 12 [2] c7 08 [2] d9 15 [2] db 14 [2] c0 12 [2] dc 15 [2] c0 3a }

  condition:
    any of them
}