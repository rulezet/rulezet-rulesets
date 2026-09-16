rule TTP_XOR_QUAD_CurrentVersionRun_ae60 {
  strings:
    $key_ae60 = { fd 0f [2] d9 01 [2] f2 2d [2] dc 0f [2] c8 14 [2] c7 0e [2] d9 13 [2] db 12 [2] c0 14 [2] dc 13 [2] c0 3c }

  condition:
    any of them
}