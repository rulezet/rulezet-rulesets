rule TTP_XOR_QUAD_CurrentVersionRun_ae2f {
  strings:
    $key_ae2f = { fd 40 [2] d9 4e [2] f2 62 [2] dc 40 [2] c8 5b [2] c7 41 [2] d9 5c [2] db 5d [2] c0 5b [2] dc 5c [2] c0 73 }

  condition:
    any of them
}