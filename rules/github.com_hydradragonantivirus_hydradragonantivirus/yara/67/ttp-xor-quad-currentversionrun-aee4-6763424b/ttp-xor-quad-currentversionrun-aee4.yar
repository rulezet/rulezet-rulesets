rule TTP_XOR_QUAD_CurrentVersionRun_aee4 {
  strings:
    $key_aee4 = { fd 8b [2] d9 85 [2] f2 a9 [2] dc 8b [2] c8 90 [2] c7 8a [2] d9 97 [2] db 96 [2] c0 90 [2] dc 97 [2] c0 b8 }

  condition:
    any of them
}