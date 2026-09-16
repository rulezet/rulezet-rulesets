rule TTP_XOR_QUAD_CurrentVersionRun_ae0a {
  strings:
    $key_ae0a = { fd 65 [2] d9 6b [2] f2 47 [2] dc 65 [2] c8 7e [2] c7 64 [2] d9 79 [2] db 78 [2] c0 7e [2] dc 79 [2] c0 56 }

  condition:
    any of them
}