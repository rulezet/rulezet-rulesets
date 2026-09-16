rule TTP_XOR_QUAD_CurrentVersionRun_ae3d {
  strings:
    $key_ae3d = { fd 52 [2] d9 5c [2] f2 70 [2] dc 52 [2] c8 49 [2] c7 53 [2] d9 4e [2] db 4f [2] c0 49 [2] dc 4e [2] c0 61 }

  condition:
    any of them
}