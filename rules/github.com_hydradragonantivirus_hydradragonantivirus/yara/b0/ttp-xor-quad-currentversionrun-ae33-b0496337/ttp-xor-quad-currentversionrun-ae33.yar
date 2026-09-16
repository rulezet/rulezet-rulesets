rule TTP_XOR_QUAD_CurrentVersionRun_ae33 {
  strings:
    $key_ae33 = { fd 5c [2] d9 52 [2] f2 7e [2] dc 5c [2] c8 47 [2] c7 5d [2] d9 40 [2] db 41 [2] c0 47 [2] dc 40 [2] c0 6f }

  condition:
    any of them
}