rule TTP_XOR_QUAD_CurrentVersionRun_ae0d {
  strings:
    $key_ae0d = { fd 62 [2] d9 6c [2] f2 40 [2] dc 62 [2] c8 79 [2] c7 63 [2] d9 7e [2] db 7f [2] c0 79 [2] dc 7e [2] c0 51 }

  condition:
    any of them
}