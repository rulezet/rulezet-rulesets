rule TTP_XOR_QUAD_CurrentVersionRun_aee5 {
  strings:
    $key_aee5 = { fd 8a [2] d9 84 [2] f2 a8 [2] dc 8a [2] c8 91 [2] c7 8b [2] d9 96 [2] db 97 [2] c0 91 [2] dc 96 [2] c0 b9 }

  condition:
    any of them
}