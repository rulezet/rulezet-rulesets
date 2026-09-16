rule TTP_XOR_QUAD_CurrentVersionRun_aee8 {
  strings:
    $key_aee8 = { fd 87 [2] d9 89 [2] f2 a5 [2] dc 87 [2] c8 9c [2] c7 86 [2] d9 9b [2] db 9a [2] c0 9c [2] dc 9b [2] c0 b4 }

  condition:
    any of them
}