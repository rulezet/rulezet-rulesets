rule TTP_XOR_QUAD_CurrentVersionRun_ae67 {
  strings:
    $key_ae67 = { fd 08 [2] d9 06 [2] f2 2a [2] dc 08 [2] c8 13 [2] c7 09 [2] d9 14 [2] db 15 [2] c0 13 [2] dc 14 [2] c0 3b }

  condition:
    any of them
}