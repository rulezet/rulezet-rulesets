rule TTP_XOR_QUAD_CurrentVersionRun_aefd {
  strings:
    $key_aefd = { fd 92 [2] d9 9c [2] f2 b0 [2] dc 92 [2] c8 89 [2] c7 93 [2] d9 8e [2] db 8f [2] c0 89 [2] dc 8e [2] c0 a1 }

  condition:
    any of them
}