rule TTP_XOR_QUAD_CurrentVersionRun_aef7 {
  strings:
    $key_aef7 = { fd 98 [2] d9 96 [2] f2 ba [2] dc 98 [2] c8 83 [2] c7 99 [2] d9 84 [2] db 85 [2] c0 83 [2] dc 84 [2] c0 ab }

  condition:
    any of them
}