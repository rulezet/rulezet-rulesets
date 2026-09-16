rule TTP_XOR_QUAD_CurrentVersionRun_ae01 {
  strings:
    $key_ae01 = { fd 6e [2] d9 60 [2] f2 4c [2] dc 6e [2] c8 75 [2] c7 6f [2] d9 72 [2] db 73 [2] c0 75 [2] dc 72 [2] c0 5d }

  condition:
    any of them
}