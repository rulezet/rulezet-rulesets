rule TTP_XOR_QUAD_CurrentVersionRun_aeeb {
  strings:
    $key_aeeb = { fd 84 [2] d9 8a [2] f2 a6 [2] dc 84 [2] c8 9f [2] c7 85 [2] d9 98 [2] db 99 [2] c0 9f [2] dc 98 [2] c0 b7 }

  condition:
    any of them
}