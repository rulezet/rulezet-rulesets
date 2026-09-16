rule TTP_XOR_QUAD_CurrentVersionRun_ae1d {
  strings:
    $key_ae1d = { fd 72 [2] d9 7c [2] f2 50 [2] dc 72 [2] c8 69 [2] c7 73 [2] d9 6e [2] db 6f [2] c0 69 [2] dc 6e [2] c0 41 }

  condition:
    any of them
}