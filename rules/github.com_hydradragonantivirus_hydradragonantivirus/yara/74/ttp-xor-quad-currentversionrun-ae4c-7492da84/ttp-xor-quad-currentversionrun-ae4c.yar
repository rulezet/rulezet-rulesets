rule TTP_XOR_QUAD_CurrentVersionRun_ae4c {
  strings:
    $key_ae4c = { fd 23 [2] d9 2d [2] f2 01 [2] dc 23 [2] c8 38 [2] c7 22 [2] d9 3f [2] db 3e [2] c0 38 [2] dc 3f [2] c0 10 }

  condition:
    any of them
}