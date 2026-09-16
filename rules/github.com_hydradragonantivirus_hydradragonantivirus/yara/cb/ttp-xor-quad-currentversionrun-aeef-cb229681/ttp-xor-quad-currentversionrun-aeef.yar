rule TTP_XOR_QUAD_CurrentVersionRun_aeef {
  strings:
    $key_aeef = { fd 80 [2] d9 8e [2] f2 a2 [2] dc 80 [2] c8 9b [2] c7 81 [2] d9 9c [2] db 9d [2] c0 9b [2] dc 9c [2] c0 b3 }

  condition:
    any of them
}