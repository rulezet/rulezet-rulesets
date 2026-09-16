rule TTP_XOR_QUAD_CurrentVersionRun_aef4 {
  strings:
    $key_aef4 = { fd 9b [2] d9 95 [2] f2 b9 [2] dc 9b [2] c8 80 [2] c7 9a [2] d9 87 [2] db 86 [2] c0 80 [2] dc 87 [2] c0 a8 }

  condition:
    any of them
}