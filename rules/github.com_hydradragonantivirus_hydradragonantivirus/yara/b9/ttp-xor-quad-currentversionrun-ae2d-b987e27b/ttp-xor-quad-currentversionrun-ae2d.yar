rule TTP_XOR_QUAD_CurrentVersionRun_ae2d {
  strings:
    $key_ae2d = { fd 42 [2] d9 4c [2] f2 60 [2] dc 42 [2] c8 59 [2] c7 43 [2] d9 5e [2] db 5f [2] c0 59 [2] dc 5e [2] c0 71 }

  condition:
    any of them
}